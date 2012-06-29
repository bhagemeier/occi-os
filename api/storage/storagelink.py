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


import uuid

from occi import backend
from occi.extensions import infrastructure
from webob import exc

from api import nova_glue


class StorageLinkBackend(backend.KindBackend):
    """
    A backend for the storage links.
    """

    def create(self, link, extras):
        """
        Creates a link from a compute instance to a storage volume.
        The user must specify what the device id is to be.
        """
        context = extras['nova_ctx']
        instance_id = get_inst_to_attach(link, context)
        volume_id = get_vol_to_attach(link, context)
        mount_point = link.attributes['occi.storagelink.deviceid']

        nova_glue.attach_volume(instance_id, volume_id, mount_point, context)

        link.attributes['occi.core.id'] = str(uuid.uuid4())
        link.attributes['occi.storagelink.deviceid'] = \
                                link.attributes['occi.storagelink.deviceid']
        link.attributes['occi.storagelink.mountpoint'] = ''
        link.attributes['occi.storagelink.state'] = 'active'

    def delete(self, link, extras):
        """
        Unlinks the the compute from the storage resource.
        """
        volume_id = get_vol_to_attach(link)
        nova_glue.detach_volume(volume_id, extras['nova_ctx'])

# HELPERS


def get_inst_to_attach(link):
    """
    Gets the compute instance that is to have the storage attached.
    """
    uid = ''
    if link.target.kind == infrastructure.COMPUTE:
        uid = link.target.attributes['occi.core.id']
    elif link.source.kind == infrastructure.COMPUTE:
        uid = link.source.attributes['occi.core.id']
    else:
        raise AttributeError('Id of the VM not found!')
    return uid


def get_vol_to_attach(link):
    """
    Gets the storage instance that is to have the compute attached.
    """
    uid = ''
    if link.target.kind == infrastructure.STORAGE:
        uid = link.target.attributes['occi.core.id']
    elif link.source.kind == infrastructure.STORAGE:
        uid = link.source.attributes['occi.core.id']
    else:
        raise AttributeError('Id of the Volume not found!')
    return uid