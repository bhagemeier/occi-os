# coding=utf-8
# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
#    Copyright (c) 2014, Intel Performance Learning Solutions Ltd.
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

"""
SDN related 'glue'

Main reason this uses python-neutronclient is that the nova internal API throw
NotImplementedErrors when creating networks:

    https://github.com/openstack/nova/blob/master/nova/network/\
        neutronv2/api.py#L1018
"""

from oslo_log import log as logging
from oslo_log import loggers

from neutronclient.neutron import client

from occi_os_api.utils import get_neutron_url


LOG = logging.getLogger(__name__)


def get_neutron_connection(context):
    token = context.auth_token
    return client.Client('2.0', endpoint_url=get_neutron_url(), token=token)


def list_networks(context):
    """
    List networks.
    """
    try:
        networks = get_neutron_connection(context).list_networks()
        return networks['networks']
    except Exception as e:
        raise AttributeError(e.message)


def create_network(context):
    """
    Create a new network with subnet.
    """
    try:
        network = {'admin_state_up': True}
        tmp = get_neutron_connection(context).create_network(
            {
                'network': network
            }
        )
        return tmp['network']['id']
    except Exception as e:
        raise AttributeError(e.message)


def retrieve_network(context, iden):
    """
    Retrieve network information.
    """
    try:
        network = get_neutron_connection(context).show_network(iden)
        return network.get('network')
    except Exception as e:
        raise AttributeError(e.message)


def delete_network(context, iden):
    """
    Delete a network.
    """

    try:
        get_neutron_connection(context).delete_network(iden)
    except Exception as e:
        raise AttributeError(e.message)


def create_subnet(context, iden, cidr, gw, dynamic=True):
    """
    Create a subnet for a network.
    """

    tenant = context.tenant
    subnet = {
        'network_id': iden,
        'ip_version': 4,
        'cidr': cidr,
        'enable_dhcp': int(dynamic),
        'gateway_ip': gw,
        'tenant_id': tenant
    }
    try:

        get_neutron_connection(context).create_subnet({'subnet': subnet})
    except Exception as e:
        raise AttributeError(e.message)


def retrieve_subnet(context, iden):
    """
    Retrieve a subnet.
    """
    try:
        return get_neutron_connection(context).show_subnet(iden)
    except Exception as e:
        raise AttributeError(e.message)


def delete_subnet(context, iden):
    """
    Delete a subnet.
    """
    try:
        return get_neutron_connection(context).delete_subnet(iden)
    except Exception as e:
        raise AttributeError(e.message)


def create_router(context, source_id, target_id):
    """
    Create a router.
    """
    neutron = get_neutron_connection(context)

    try:

        router = neutron.create_router(
            {'router': {'name': 'occirouter'}}
        )
        subnets = neutron.list_subnets(network_id=source_id)
        if len(subnets.get('subnets')) > 0:
            subnet = subnets['subnets'][0]
            neutron.add_interface_router(
                router['router']['id'],
                {'subnet_id': subnet['id']}
            )
            neutron.add_gateway_router(
                router['router']['id'],
                {'network_id': target_id}
            )
        return router
    except Exception as e:
        raise AttributeError(e.message)


def delete_router(context, router_id, network_id):
    """
    Remove a router.
    """
    neutron = get_neutron_connection(context)

    try:

        neutron.remove_gateway_router(router_id)
        subnet = neutron.list_subnets(network_id=network_id)['subnets'][0]
        neutron.remove_interface_router(router_id, {'subnet_id': subnet['id']})
        neutron.delete_router(router_id)
    except Exception as err:
        raise AttributeError(err)


def add_floating_ip(context, iden, network_id):
    """
    Add a floating ip.
    """

    try:
        port = list_ports(context, device_id=iden)

        if len(port) == 0:
            return None
        else:
            body = {'floatingip': {
                'floating_network_id': network_id,
                'port_id': port[0]['id']}
            }
            floating_ip = get_neutron_connection(
                context
            ).create_floatingip(
                body
            )

        return floating_ip
    except Exception as e:
        raise AttributeError(e.message)


def remove_floating_ip(context, iden):
    """
    Remove a floating ip.
    """

    try:
        get_neutron_connection(context).delete_floatingip(iden)
    except Exception as err:
        raise AttributeError(err)


def retrieve_port(context, iden, **kwargs):
    """
    Retrieve port information.
    """
    try:
        port = get_neutron_connection(context).show_port(
            iden,
            **kwargs
        )
        return port['port']
    except Exception as e:
        raise AttributeError(e.message)


def list_ports(context, **kwargs):
    """
    List ports
    """
    ports = get_neutron_connection(context).list_ports(
        **kwargs
    )
    return ports['ports']


def get_port_status(context, iden):
    """
    Retrieve port status.
    """
    port = get_neutron_connection(context).show_port(iden)
    return port['port']['status']


def port_up(context, iden):
    """
    Set network port state to True
    """
    try:
        if get_port_status(context, iden) != 'ACTIVE':
            get_neutron_connection(context).update(iden, admin_state_up=True)
    except Exception as e:
        raise AttributeError(e.message)


def port_down(context, iden):
    """
    Set network port state to False
    """
    try:
        if get_port_status(context, iden) == 'ACTIVE':
            get_neutron_connection(context).update(iden, admin_state_up=False)
    except Exception as e:
        raise AttributeError(e.message)
