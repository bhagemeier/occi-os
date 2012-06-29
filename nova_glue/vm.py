# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
#    Copyright (c) 2012, Intel Performance Learning Solutions Ltd.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from api.compute import templates
from api.extensions import occi_future
from api.extensions import openstack

from nova import compute
from nova import exception
from nova import utils
from nova.compute import vm_states
from nova.compute import task_states
from nova.compute import instance_types
from nova.flags import FLAGS

from nova_glue import vol

from occi import exceptions
from occi.extensions import infrastructure

import logging

# Connection to the nova APIs

compute_api = compute.API()

LOG = logging.getLogger()


def create_vm(entity, context):
    """
    Create a VM for an given OCCI entity.

    entity -- the OCCI resource entity.
    context -- the os context.
    """
    if 'occi.compute.hostname' in entity.attributes:
        name = entity.attributes['occi.compute.hostname']
    else:
        name = 'None'
    key_name = key_data = None
    password = utils.generate_password(FLAGS.password_length)
    access_ip_v4 = None
    access_ip_v6 = None
    user_data = None
    metadata = {}
    injected_files = []
    min_count = max_count = 1
    requested_networks = None
    sg_names = []
    availability_zone = None
    config_drive = None
    block_device_mapping = None
    kernel_id = ramdisk_id = None
    auto_disk_config = None
    scheduler_hints = None

    rc = oc = 0
    resource_template = None
    os_template = None
    for mixin in entity.mixins:
        if isinstance(mixin, templates.ResourceTemplate):
            resource_template = mixin
            rc += 1
        elif isinstance(mixin, templates.OsTemplate):
            os_template = mixin
            oc += 1
        elif mixin == openstack.OS_KEY_PAIR_EXT:
            attr = 'org.openstack.credentials.publickey.name'
            key_name = entity.attributes[attr]
            attr = 'org.openstack.credentials.publickey.data'
            key_data = entity.attributes[attr]
        elif mixin == openstack.OS_ADMIN_PWD_EXT:
            password = entity.attributes['org.openstack.credentials'\
                                         '.admin_pwd']
        elif mixin == openstack.OS_ACCESS_IP_EXT:
            attr = 'org.openstack.network.access.version'
            if entity.attributes[attr] == 'ipv4':
                access_ip_v4 = entity.attributes['org.openstack.network'\
                                                 '.access.ip']
            elif entity.attributes[attr] == 'ipv6':
                access_ip_v6 = entity.attributes['org.openstack.network'\
                                                 '.access.ip']
            else:
                raise AttributeError('No ip given within the attributes!')

        # Look for security group. If the group is non-existant, the
        # call to create will fail.
        if occi_future.SEC_GROUP in mixin.related:
            sg_names.append(mixin.term)

    flavor_name = resource_template.term
    image_id = os_template.os_id

    if flavor_name:
        inst_type = compute.instance_types.get_instance_type_by_name\
            (flavor_name)
    else:
        inst_type = compute.instance_types.get_default_instance_type()
        msg = ('No resource template was found in the request. '
               'Using the default: %s') % inst_type['name']
        LOG.warn(msg)
    # make the call
    try:
        (instances, _reservation_id) = compute_api.create(
            context=context,
            instance_type=inst_type,
            image_href=image_id,
            kernel_id=kernel_id,
            ramdisk_id=ramdisk_id,
            min_count=min_count,
            max_count=max_count,
            display_name=name,
            display_description=name,
            key_name=key_name,
            key_data=key_data,
            security_group=sg_names,
            availability_zone=availability_zone,
            user_data=user_data,
            metadata=metadata,
            injected_files=injected_files,
            admin_password=password,
            block_device_mapping=block_device_mapping,
            access_ip_v4=access_ip_v4,
            access_ip_v6=access_ip_v6,
            requested_networks=requested_networks,
            config_drive=config_drive,
            auto_disk_config=auto_disk_config,
            scheduler_hints=scheduler_hints)
    except Exception as error:
        raise AttributeError(str(error))

    # return first instance
    return instances[0]


def rebuild_vm(uid, image_href, context):
    """
    Rebuilds the specified VM with the supplied OsTemplate mixin.

    uid -- id of the instance
    image_href -- image reference.
    context -- the os context
    """
    instance = _get_vm(uid, context)

    admin_password = utils.generate_password(FLAGS.password_length)
    kwargs = {}
    try:
        compute_api.rebuild(context, instance, image_href, admin_password,
                            **kwargs)
    except exception.InstanceInvalidState:
        raise exceptions.HTTPError(409, 'VM is in an invalid state.')
    except exception.ImageNotFound:
        raise AttributeError('Cannot find image for rebuild')


def resize_vm(uid, flavor_name, context):
    """
    Resizes a VM up or down

    Update: libvirt now supports resize see:
    http://wiki.openstack.org/HypervisorSupportMatrix

    uid -- id of the instance
    flavor_name -- image reference.
    context -- the os context
    """
    instance = _get_vm(uid, context)
    kwargs = {}
    try:
        flavor = instance_types.get_instance_type_by_name(flavor_name)
        compute_api.resize(context, instance, flavor_id=flavor['flavorid'],
                           **kwargs)
    except exception.FlavorNotFound:
        raise AttributeError('Unable to locate requested flavor.')
    except exception.CannotResizeToSameSize:
        raise AttributeError('Resize requires a change in size.')
    except exception.InstanceInvalidState:
        raise exceptions.HTTPError(409, 'VM is in an invalid state.')


def delete_vm(uid, context):
    """
    Destroy a VM.

    uid -- id of the instance
    context -- the os context
    """
    instance = _get_vm(uid, context)

    if FLAGS.reclaim_instance_interval:
        compute_api.soft_delete(context, instance)
    else:
        compute_api.delete(context, instance)


def suspend_vm(uid, context):
    """
    Suspends a VM. Use the start action to unsuspend a VM.

    uid -- id of the instance
    context -- the os context
    """
    instance = _get_vm(uid, context)

    try:
        compute_api.pause(context, instance)
    except Exception as error:
        raise exceptions.HTTPError(500, str(error))


def snapshot_vm(uid, image_name, context):
    """
    Snapshots a VM. Use the start action to unsuspend a VM.

    uid -- id of the instance
    image_name -- name of the new image
    context -- the os context
    """
    instance = _get_vm(uid, context)
    try:
        compute_api.snapshot(context,
                             instance,
                             image_name)

    except exception.InstanceInvalidState:
        raise AttributeError('VM is not in an valid state.')


def start_vm(uid, state, context):
    """
    Starts a vm that is in the stopped state. Note, currently we do not
    use the nova start and stop, rather the resume/suspend methods. The
    start action also unpauses a paused VM.

    uid -- id of the instance
    state -- the state the VM is in (str)
    context -- the os context
    """
    instance = _get_vm(uid, context)

    try:
        if state == 'suspended':
            compute_api.unpause(context, instance)
        else:
            compute_api.resume(context, instance)
    except Exception as error:
        raise exceptions.HTTPError(500, 'Error while starting VM: ' + str
            (error))


def stop_vm(uid, context):
    """
    Stops a VM. Rather than use stop, suspend is used.
    OCCI -> graceful, acpioff, poweroff
    OS -> unclear

    uid -- id of the instance
    context -- the os context
    """
    instance = _get_vm(uid, context)

    try:
        # TODO(dizz): There are issues with the stop and start methods of
        #             OS. For now we'll use suspend.
        # self.compute_api.stop(context, instance)
        compute_api.suspend(context, instance)
    except Exception as error:
        raise exceptions.HTTPError(500, 'Error while stopping VM: ' + str
            (error))


def restart_vm(uid, method, context):
    """
    Restarts a VM.
      OS types == SOFT, HARD
      OCCI -> graceful, warm and cold
      mapping:
      - SOFT -> graceful, warm
      - HARD -> cold

    uid -- id of the instance
    method -- how the machine should be restarted.
    context -- the os context
    """
    instance = _get_vm(uid, context)

    if method in ('graceful', 'warm'):
        reboot_type = 'SOFT'
    elif method is 'cold':
        reboot_type = 'HARD'
    else:
        raise AttributeError('Unknown method.')
    try:
        compute_api.reboot(context, instance, reboot_type)
    except exception.InstanceInvalidState:
        raise exceptions.HTTPError(409, 'VM is in an invalid state.')
    except Exception as e:
        msg = ("Error in reboot %s") % e
        raise exceptions.HTTPError(500, msg)


def attach_volume(instance_id, volume_id, mount_point, context):
    """
    Attaches a storage volume.

    instance_id -- Id of the VM.
    volume_id -- Id of the storage volume.
    mount_point -- Where to mount.
    context -- The os security context.
    """
    # TODO: check exception handling!
    instance = _get_vm(instance_id, context)
    volume_id =  vol._get_volume(volume_id, context)[0]

    compute_api.attach_volume(
        context,
        instance,
        volume_id,
        mount_point)


def detach_volume(volume_id, context):
    """
    Detach a storage volume.

    volume_id -- Id of the volume.
    context -- the os context.
    """
    volume_id =  vol._get_volume(volume_id, context)[0]

    compute_api.detach_volumne(context, volume_id)


def set_password_for_vm(uid, password, context):
    """
    Set new password for an VM.

    uid -- Id of the instance.
    password -- The new password.
    context -- The os context.
    """
    # TODO: check exception handling!
    instance = _get_vm(uid, context)

    compute_api.set_admin_password(context, instance, password)


def get_vnc(uid, context):
    """
    Retrieve VNC console.

    uid -- id of the instance
    context -- the os context
    """
    instance = _get_vm(uid, context)
    try:
        console = compute_api.get_vnc_console(context, instance, 'novnc')
    except Exception:
        LOG.warn('Console info is not available yet.')
        return None
    return console


def revert_resize_vm(uid, context):
    """
    Revert a resize.

    uid -- id of the instance
    context -- the os context
    """
    instance = _get_vm(uid, context)
    try:
        compute_api.revert_resize(context, instance)
    except exception.MigrationNotFound:
        raise AttributeError('Instance has not been resized.')
    except exception.InstanceInvalidState:
        raise exceptions.HTTPError(409, 'VM is an invalid state.')
    except Exception:
        raise AttributeError('Error in revert-resize.')


def confirm_resize_vm(uid, context):
    """
    Confirm a resize.

    uid -- id of the instance
    context -- the os context
    """
    instance = _get_vm(uid, context)
    try:
        compute_api.confirm_resize(context, instance)
    except exception.MigrationNotFound:
        raise AttributeError('Instance has not been resized.')
    except exception.InstanceInvalidState:
        raise exceptions.HTTPError(409, 'VM is an invalid state.')
    except Exception:
        raise AttributeError('Error in confirm-resize.')


def _get_vm(uid, context):
    """
    Retrieve an VM instance from nova.

    uid -- id of the instance
    context -- the os context
    """
    try:
        instance = compute_api.get(context, uid)
    except exception.NotFound:
        raise exceptions.HTTPError(404, 'VM not found!')
    return instance


def get_occi_state(uid, context):
    """
    See nova/compute/vm_states.py nova/compute/task_states.py

    Mapping assumptions:
    - active == VM can service requests from network. These requests
            can be from users or VMs
    - inactive == the oppose! :-)
    - suspended == machine in a frozen state e.g. via suspend or pause

    uid -- Id of the VM.
    context -- the os context.
    """
    instance = _get_vm(uid, context)

    if instance['vm_state'] in (vm_states.ACTIVE,
                                task_states.UPDATING_PASSWORD,
                                task_states.RESIZE_CONFIRMING):
        return 'active', [infrastructure.STOP,
                          infrastructure.SUSPEND,
                          infrastructure.RESTART,
                          openstack.OS_CONFIRM_RESIZE,
                          openstack.OS_REVERT_RESIZE,
                          openstack.OS_CHG_PWD,
                          openstack.OS_CREATE_IMAGE]

        # reboot server - OS, OCCI
        # start server - OCCI
    elif instance['vm_state'] in (task_states.STARTING,
                                  task_states.POWERING_ON,
                                  task_states.REBOOTING,
                                  task_states.REBOOTING_HARD):
        return 'inactive', []

        # pause server - OCCI, suspend server - OCCI, stop server - OCCI
    elif instance['vm_state'] in (task_states.STOPPING,
                                  task_states.POWERING_OFF):
        return 'inactive', [infrastructure.START]

        # resume server - OCCI
    elif instance['vm_state'] in (task_states.RESUMING,
                                  task_states.PAUSING,
                                  task_states.SUSPENDING):
        if instance['vm_state'] in (vm_states.PAUSED,
                                    vm_states.SUSPENDED):
            return 'suspended', [infrastructure.START]
        else:
            return 'suspended', []

            # rebuild server - OS
            # resize server confirm rebuild
            # revert resized server - OS (indirectly OCCI)
    elif instance['vm_state'] in [vm_states.RESIZED, vm_states.BUILDING,
                                  task_states.RESIZE_CONFIRMING,
                                  task_states.RESIZE_FINISH,
                                  task_states.RESIZE_MIGRATED,
                                  task_states.RESIZE_MIGRATING,
                                  task_states.RESIZE_PREP,
                                  task_states.RESIZE_REVERTING]:
        return 'inactive', []