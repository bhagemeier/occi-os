OCCI for OpenStack
==================

***NOTE: This project will be moving to [stackforge](https://github.com/stackforge/occi-os) ***

This is a clone and continuation of https://github.com/dizz/nova (no longer available) - it
provides a python egg which can be easily deployed in [OpenStack](http://www
.openstack.org) and will thereby add the 3rd party [OCCI](http://www.occi-wg
.org) interface to OpenStack. For usage examples, [see the OpenStack wiki]
(http://wiki.openstack.org/occi).

Usage
-----

0. Install dependencies: `pip install pyssf`
1. Install this egg: `python setup.py install` (or `pip install
openstackocci-icehouse`)
2. Configure OpenStack - Add application to `api-paste.ini` of nova and
enable the API

***Note***: do not install the [occi](http://pypi.python.org/pypi/occi/0.6)
package via `pip`. This is a seperate project and not related to OpenStack &
 OCCI.

### Configuration

Make sure an application is configured in `api-paste.ini` (name can be
picked yourself):

	########
	# OCCI #
	########

	[composite:occiapi]
	use = egg:Paste#urlmap
	/: occiapppipe

	[pipeline:occiapppipe]
	pipeline = authtoken keystonecontext occiapp
	# with request body size limiting and rate limiting
	# pipeline = sizelimit authtoken keystonecontext ratelimit occiapp

	[app:occiapp]
	use = egg:openstackocci-icehouse#occi_app

Make sure the API (name from above) is enabled in `nova.conf`:

	[...]
	enabled_apis=ec2,occiapi,osapi_compute,osapi_volume,metadata
	[...]

#### Register service in keystone
You can register the OCCI service endpoint in Keyston via the following commands. First you need to create the OCCI service via

	$ keystone service-create --name occi_api --type occi --description 'Nova OCCI Service'
	+-------------+----------------------------------+
	|   Property  |              Value               |
	+-------------+----------------------------------+
	| description |           OCCI service           |
	|      id     | 8e6de5d0d7624584bed6bec9bef7c9e0 |
	|     name    |             occi_api             |
	|     type    |               occi               |
	+-------------+----------------------------------+

from which you get the new service ID and use it to register the OCCI endpoint in Keystone:

	$ keystone endpoint-create --service_id 8e6de5d0d7624584bed6bec9bef7c9e0 --region RegionOne --publicurl http://$HOSTNAME:8787/ --internalurl  http://$HOSTNAME:8787/ --adminurl http://$HOSTNAME:8787/
	
#### Hacking the port number

(Optional) You can set the port option via the `nova.conf` configuration
file - default is 8787:

    [...]
    occiapi_listen_port=9999
    [...]

There is further documentation on [setting up your development environment
in the wiki](https://github.com/tmetsch/occi-os/wiki/DevEnv).

#Versioning

The general naming scheme for the Python eggs is:

* openstackocci - for the latest and greatest
* openstackocci-\<openstack release name\> - for OpenStack release specific stable releases

# Deployment using Puppet
This library can be integrated using puppet as a configuration management tool.
See [this blog post for more details](http://www.cloudcomp.ch/2012/09/automating-occi-installations/).

