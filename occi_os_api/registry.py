# coding=utf-8
# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2012, Intel Performance Learning Solutions Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
OCCI registry
"""

# R0201:method could be func.E1002:old style obj,R0914-R0912:# of branches
# E1121:# positional args.
# pylint: disable=R0201,E1002,R0914,R0912,E1121

import uuid
from oslo_log import log as logging
from oslo_log import loggers

from oslo.config import cfg
from occi import registry as occi_registry
from occi import core_model
from occi.extensions import infrastructure

from occi_os_api.backends import openstack
from occi_os_api.extensions import os_addon
from occi_os_api.nova_glue import vm
from occi_os_api.nova_glue import storage
from occi_os_api.nova_glue import net
from occi_os_api.nova_glue import security
from occi_os_api.nova_glue import neutron
from occi_os_api.utils import is_compute, is_network, is_sec_rule, \
    is_sec_group, is_networkinterface, is_storage, get_item_id


LOG = logging.getLogger(__name__)

CONF = cfg.CONF


class OCCIRegistry(occi_registry.NonePersistentRegistry):

    """
    Registry for OpenStack.

    Idea is the following: Create the OCCI entities (Resource and their
    links) here and let the backends handle actions, updates the attributes
    etc.
    """

    def __init__(self):
        super(OCCIRegistry, self).__init__()
        self.cache = {}

    def set_hostname(self, hostname):
        if CONF.occi_custom_location_hostname:
            hostname = CONF.occi_custom_location_hostname
        super(OCCIRegistry, self).set_hostname(hostname)

    def get_extras(self, extras):
        """
        Get data which is encapsulated in the extras.
        """
        sec_extras = None
        if extras is not None:
            sec_extras = {'user_id': extras['nova_ctx'].user_id,
                          'project_id': extras['nova_ctx'].project_id}
        return sec_extras

    # The following two are here to deal with the security group mixins

    def delete_mixin(self, mixin, extras):
        """
        Allows for the deletion of user defined mixins.
        If the mixin is a security group mixin then that mixin's
        backend is called.
        """
        if (hasattr(mixin, 'related') and
                os_addon.SEC_GROUP in mixin.related):
            backend = self.get_backend(mixin, extras)
            backend.destroy(mixin, extras)

        super(OCCIRegistry, self).delete_mixin(mixin, extras)

    def set_backend(self, category, backend, extras):
        """
        Assigns user id and tenant id to user defined mixins
        """
        if (hasattr(category, 'related') and
                os_addon.SEC_GROUP in category.related):
            backend = openstack.SecurityGroupBackend()
            backend.init_sec_group(category, extras)

        super(OCCIRegistry, self).set_backend(category, backend, extras)

    # The following two deal with the creation and deletion os links.

    def add_resource(self, key, resource, extras):
        """
        Just here to prevent the super class from filling up an unused dict.
        """

        if (key, extras['nova_ctx'].user_id) not in self.cache and \
                core_model.Link.kind in resource.kind.related:
            # don't need to cache twice, only adding links :-)
            self.cache[(key, extras['nova_ctx'].user_id)] = resource
        elif (key, extras['nova_ctx'].user_id) not in self.cache and \
                resource.kind == os_addon.SEC_RULE:
            # don't need to cache twice, only adding links :-)
            self.cache[(key, extras['nova_ctx'].user_id)] = resource

        LOG.debug(
            "Adding resource %s" % key
        )

    def delete_resource(self, key, extras):
        """
        Just here to prevent the super class from messing up.
        """
        if (key, extras['nova_ctx'].user_id) in self.cache:
            self.cache.pop((key, extras['nova_ctx'].user_id))

        LOG.debug(
            "Deleting resource %s" % key
        )

    # the following routines actually retrieve the info form OpenStack. Note
    # that a cache is used. The cache is stable - so delete resources
    # eventually also get deleted form the cache.

    def update_resource(self, item, result, res_ids, extras):

        item_id = get_item_id(item)

        if item.extras is None:
            # add to result set
            result.append(item)
        elif item_id in res_ids.get('network') and is_network(item.kind):
            # check & update (take links, mixins from cache)
            # add compute and it's links to result
            self._update_occi_network(item, extras)
            result.append(item)
        elif item_id in res_ids.get('compute') and is_compute(item.kind):
            # check & update (take links, mixins from cache)
            # add compute and it's links to result
            self._update_occi_compute(item, extras)
            result.append(item)
            result.extend(item.links)
        elif item_id in res_ids.get('storage') and is_storage(item.kind):
            # check & update (take links, mixins from cache)
            # add compute and it's links to result
            self._update_occi_storage(item, extras)
            result.append(item)
        elif item_id in res_ids.get('sec_group') and is_sec_group(item.kind):
            # check & update (take links, mixins from cache)
            # add compute and it's links to result
            self._update_occi_security_group(item, extras)
            result.append(item)
        elif item_id in res_ids.get('sec_rule') and is_sec_rule(item.kind):
            # check & update (take links, mixins from cache)
            # add compute and it's links to result
            self._update_occi_security_rule(item, extras)
            result.append(item)
        elif item_id not in res_ids.get('network') and is_network(item.kind):
            # remove item and it's links from cache!
            for link in item.links:
                self.cache.pop((link.identifier, item.extras['user_id']))
            self.cache.pop((item.identifier, item.extras['user_id']))
        elif item_id not in res_ids.get('compute') and is_compute(item.kind):
            # remove item and it's links from cache!
            for link in item.links:
                self.cache.pop((link.identifier, item.extras['user_id']))
            self.cache.pop((item.identifier, item.extras['user_id']))
        elif item_id not in res_ids.get('storage') and is_storage(item.kind):
            # remove item
            self.cache.pop((item.identifier, item.extras['user_id']))

        return result

    def get_resource(self, key, extras):
        """
        Retrieve a single resource.
        """
        context = extras['nova_ctx']
        iden = key[key.rfind('/') + 1:]
        LOG.debug(
            "Getting Openstack resource %s" % iden
        )
        res_ids = OCCIRegistry.get_resource_ids(
            context,
            ['network', 'network_port', 'storage', 'sec_rule', 'sec_group',
             'compute'])

        if (key, context.user_id) in self.cache:
            # I have seen it - need to update or delete if gone in OS!
            # I have already seen it
            cached_item = self.cache[(key, context.user_id)]
            if iden not in res_ids.get('network') and is_network(
                    cached_item.kind):
                # it was delete in OS -> remove from cache + KeyError!
                # can delete it because it was my item!
                self.cache.pop((key, repr(extras)))
                raise KeyError
            if iden not in res_ids.get('network_port') \
                    and is_networkinterface(cached_item.kind):
                self.cache.pop((key, repr(extras)))
                raise KeyError
            if iden not in res_ids.get('compute') and is_compute(
                    cached_item.kind):
                # it was delete in OS -> remove links, cache + KeyError!
                # can delete it because it was my item!
                for link in cached_item.links:
                    self.cache.pop((link.identifier, repr(extras)))
                self.cache.pop((key, repr(extras)))
                raise KeyError
            if iden not in res_ids.get('storage') and is_storage(
                    cached_item.kind):
                # it was delete in OS -> remove from cache + KeyError!
                # can delete it because it was my item!
                self.cache.pop((key, repr(extras)))
                raise KeyError
            if iden not in res_ids.get('sec_group') and is_sec_group(
                    cached_item.kind):
                # it was delete in OS -> remove from cache + KeyError!
                # can delete it because it was my item!
                self.cache.pop((key, repr(extras)))
                raise KeyError
            if iden not in res_ids.get('sec_rule') and is_sec_rule(
                    cached_item.kind):
                # it was delete in OS -> remove from cache + KeyError!
                # can delete it because it was my item!
                self.cache.pop((key, repr(extras)))
                raise KeyError
            elif iden in res_ids.get('network'):
                # it also exists in OS -> update it!
                result = self._update_occi_network(cached_item, extras)
            elif iden in res_ids.get('compute'):
                # it also exists in OS -> update it (take links, mixins
                # from cached one)
                result = self._update_occi_compute(cached_item, extras)
            elif iden in res_ids.get('sec_rule'):
                result = self._update_occi_security_rule(cached_item, extras)
            elif iden in res_ids.get('storage'):
                # it also exists in OS -> update it!
                result = self._update_occi_storage(cached_item, extras)
            else:
                # return cached item (links)
                return cached_item
        elif (key, None) in self.cache:
            # return shared entities from cache!
            return self.cache[(key, None)]
        else:
            # construct it.
            if iden in res_ids.get('network'):
                result = self._construct_occi_network(iden, extras)[0]
            elif iden in res_ids.get('compute'):
                result = self._construct_occi_compute(iden, extras)[0]
            elif iden in res_ids.get('storage'):
                result = self._construct_occi_storage(iden, extras)[0]
            elif iden in res_ids.get('network_port'):
                result = self._construct_occi_networkinterface(iden, extras)[0]
            elif iden in res_ids.get('sec_group'):
                result = self._construct_occi_security_group(iden, extras)[0]
            elif iden in res_ids.get('sec_rule'):
                result = self._construct_occi_security_rule(iden, extras)[0]
            else:
                # doesn't exist!
                raise KeyError

        if result.identifier != key:
            raise AttributeError('Key/identifier mismatch! Requested: ' +
                                 key + ' Got: ' + result.identifier)
        return result

    def get_resource_keys(self, extras):
        """
        Retrieve the keys of all resources.
        """
        keys = []
        for item in self.cache.values():
            if item.extras is not None and item.extras != extras:
                # filter out items not belonging to this user!
                continue
            else:
                # add identifier
                keys.append(item.identifier)

        return keys

    def get_resources(self, extras):
        """
        Retrieve a set of resources.
        """
        LOG.debug(
            "Getting Openstack resources"
        )
        context = extras['nova_ctx']
        result = []

        res_ids = OCCIRegistry.get_resource_ids(
            context,
            ['network', 'network_port', 'storage', 'sec_rule', 'sec_group',
             'compute'])

        for item in self.cache.values():
            if item.extras is not None and item.extras['user_id'] != \
                    context.user_id:
                # filter out items not belonging to this user!
                continue
            self.update_resource(item, result, res_ids, extras)

        for item in res_ids.get('network'):
            if (infrastructure.NETWORK.location + item,
                    context.user_id) in self.cache:
                continue
            else:
                # construct (with links and mixins and add to cache!
                ent_list = self._construct_occi_network(item, extras)
                result.extend(ent_list)
        for item in res_ids.get('sec_group'):
            if (os_addon.SEC_GROUP.location + item,
                    context.user_id) in self.cache:
                continue
            else:
                # construct (with links and mixins and add to cache!
                ent_list = self._construct_occi_security_group(item, extras)
                result.extend(ent_list)
        for item in res_ids.get('sec_rule'):
            if (os_addon.SEC_RULE.location + item,
                    context.user_id) in self.cache:
                continue
            else:
                # construct (with links and mixins and add to cache!
                ent_list = self._construct_occi_security_rule(item, extras)
                result.extend(ent_list)
        for item in res_ids.get('compute'):
            if (infrastructure.COMPUTE.location + item,
                    context.user_id) in self.cache:
                continue
            else:
                # construct (with links and mixins and add to cache!
                # add compute and it's links to result
                ent_list = self._construct_occi_compute(item, extras)
                result.extend(ent_list)
        for item in res_ids.get('storage'):
            if (infrastructure.STORAGE.location + item,
                    context.user_id) in self.cache:
                continue
            else:
                # construct (with links and mixins and add to cache!
                # add compute and it's links to result
                ent_list = self._construct_occi_storage(item, extras)
                result.extend(ent_list)
        return result

    # Not part of parent

    def _update_occi_compute(self, entity, extras):
        """
        Update an occi compute resource instance.
        """
        return entity

    def _construct_occi_compute(self, identifier, extras):
        """
        Construct a OCCI compute instance.

        First item in result list is entity self!

        Adds it to the cache too!
        """
        result = []
        context = extras['nova_ctx']

        LOG.debug(
            "Constructing compute  %s." % identifier
        )

        instance = vm.get_vm(identifier, context)

        # 1. get identifier
        iden = infrastructure.COMPUTE.location + identifier
        entity = core_model.Resource(iden, infrastructure.COMPUTE,
                                     [os_addon.OS_VM])
        result.append(entity)

        # 2. os and res templates
        flavor_id = int(instance['instance_type_id'])
        res_tmp = self.get_category('/' + str(flavor_id) + '/', extras)
        if res_tmp:
            entity.mixins.append(res_tmp)

        os_id = instance['image_ref']
        image_id = vm.retrieve_image(os_id, context)['id']
        image_tmp = self.get_category('/' + image_id + '/', extras)
        if image_tmp:
            entity.mixins.append(image_tmp)

        # 3. network links & get links from cache!
        net_links = net.get_network_details(identifier, context)

        for item in net_links:
            source = self.get_resource(
                infrastructure.NETWORK.location +
                str(item.get('net_id')),
                extras
            )
            link = core_model.Link(
                infrastructure.NETWORKINTERFACE.location +
                str(item.get('vif')),
                infrastructure.NETWORKINTERFACE,
                [],
                source,
                entity
            )
            link.attributes['occi.core.id'] = str(item.get('vif'))
            link.extras = self.get_extras(extras)
            source.links.append(link)
            result.append(link)
            self.cache[(link.identifier, context.user_id)] = link

        # core.id and cache it!
        entity.attributes['occi.core.id'] = identifier
        entity.extras = self.get_extras(extras)
        self.cache[(entity.identifier, context.user_id)] = entity

        return result

    def _update_occi_storage(self, entity, extras):
        """
        Update a storage resource instance.
        """
        return entity

    def _construct_occi_storage(self, identifier, extras):
        """
        Construct a OCCI storage instance.

        First item in result list is entity self!

        Adds it to the cache too!
        """
        result = []
        context = extras['nova_ctx']

        LOG.debug(
            "Constructing storage  %s." % identifier
        )

        stor = storage.get_storage(identifier, context)

        # id, display_name, size, status
        iden = infrastructure.STORAGE.location + identifier
        entity = core_model.Resource(iden, infrastructure.STORAGE, [])
        result.append(entity)

        # create links on VM resources
        if stor['status'] == 'in-use':
            iden = str(uuid.uuid4())
            source = self.get_resource(
                infrastructure.COMPUTE.location +
                str(stor.get('instance_uuid')),
                extras
            )
            link = core_model.Link(
                infrastructure.STORAGELINK.location +
                iden,
                infrastructure.STORAGELINK,
                [],
                source,
                entity
            )
            link.attributes['occi.core.id'] = iden
            link.extras = self.get_extras(extras)
            source.links.append(link)
            result.append(link)
            self.cache[(link.identifier, context.user_id)] = link

        # core.id and cache it!
        entity.attributes['occi.core.id'] = identifier
        entity.extras = self.get_extras(extras)
        self.cache[(entity.identifier, context.user_id)] = entity

        return result

    def _update_occi_network(self, entity, extras):
        """
        Update a network resource.
        """
        return entity

    def _construct_occi_network(self, identifier, extras):
        """
        Create a network resource.
        """
        result = []
        context = extras['nova_ctx']

        LOG.debug(
            "Constructing network  %s." % identifier
        )

        network = neutron.retrieve_network(context, identifier)
        mixins = []
        if len(network['subnets']) > 0:
            mixins = [infrastructure.IPNETWORK]

        iden = infrastructure.NETWORK.location + identifier
        entity = core_model.Resource(iden, infrastructure.NETWORK, mixins)
        entity.attributes['occi.core.id'] = identifier
        entity.extras = self.get_extras(extras)
        self.cache[(entity.identifier, context.user_id)] = entity
        result.append(entity)

        # TODO: deal with routers!
        return result

    def _construct_occi_networkinterface(self, identifier, extras):
        """
        Create a network interface resource.
        """
        result = []
        context = extras['nova_ctx']

        LOG.debug(
            "Constructing network interface  %s." % identifier
        )

        item = neutron.retrieve_port(context, identifier)
        iden = infrastructure.NETWORKINTERFACE.location + identifier
        # get network resource
        entity = self.get_resource(
            infrastructure.COMPUTE.location + str(item.get('device_id')),
            extras
        )
        # get compute resource
        source = self.get_resource(
            infrastructure.NETWORK.location + str(item.get('network_id')),
            extras
        )
        # create link
        link = core_model.Link(
            infrastructure.NETWORKINTERFACE.location + item.get('id'),
            infrastructure.NETWORKINTERFACE,
            [],
            source,
            entity
        )
        link.attributes['occi.core.id'] = iden
        link.extras = self.get_extras(extras)
        source.links.append(link)
        result.append(link)
        self.cache[(link.identifier, context.user_id)] = link
        return result

    def _construct_occi_security_rule(self, identifier, extras):
        """
        Contruct security rule
        """
        result = []
        context = extras['nova_ctx']
        LOG.debug(
            "Constructing security rule  %s." % identifier
        )
        mixins = []

        iden = os_addon.SEC_RULE.location + identifier
        entity = core_model.Resource(iden, os_addon.SEC_RULE, mixins)
        entity.attributes['occi.core.id'] = identifier
        entity.extras = self.get_extras(extras)
        self.cache[(entity.identifier, context.user_id)] = entity
        result.append(entity)

        return result

    def _update_occi_security_group(self, entity, extras):
        """
        Update security group
        """
        return entity

    def _construct_occi_security_group(self, identifier, extras):
        """
        Construct security group
        """
        result = []
        context = extras['nova_ctx']

        mixins = []

        LOG.debug("Constructing security group %s" % identifier)

        group = security.retrieve_group(identifier, context)

        if len(group.get('rules')) > 0:
            for rule in group.get('rules'):
                self._construct_occi_security_rule(
                    rule.get('id'),
                    extras
                )
            mixins = [os_addon.SEC_RULE]

        iden = os_addon.SEC_GROUP.location + identifier
        entity = core_model.Resource(iden, os_addon.SEC_GROUP, mixins)
        entity.attributes['occi.core.id'] = identifier
        entity.extras = self.get_extras(extras)
        self.cache[(entity.identifier, context.user_id)] = entity
        result.append(entity)

        return result

    def _update_occi_security_rule(self, entity, extras):
        return entity

    @staticmethod
    def get_resource_ids(context, resource_names):
        """

        :rtype : dictionary of ids
        """
        LOG.debug("Getting resource ids from %s" % resource_names)

        resources = {}

        if 'compute' in resource_names:
            vms = vm.get_vms(context)
            resources['compute'] = \
                [item.get('uuid') for item in vms if item.get('uuid')]
        if 'storage' in resource_names:
            stors = storage.get_storage_volumes(context)
            resources['storage'] = \
                [item.get('id') for item in stors if item.get('id')]
        if 'network' in resource_names:
            nets = neutron.list_networks(context)
            resources['network'] = \
                [item.get('id') for item in nets if item.get('id')]
        if 'network_port' in resource_names:
            ports = neutron.list_ports(context)
            resources['network_port'] = \
                [item.get('id') for item in ports if item.get('id')]
        if 'sec_group' in resource_names:
            sec_groups = security.retrieve_groups_by_project(context)
            resources['sec_group'] = \
                [item.get('id') for item in sec_groups if item.get('id')]
        if 'sec_rule' in resource_names:
            sec_groups = security.retrieve_groups_by_project(context)
            sec_rules = [rule.get('rules')
                         for rule in sec_groups if rule.get('rules')][0]
            resources['sec_rule'] = \
                [rule.get('id') for rule in sec_rules if rule.get('id')]

        return resources
