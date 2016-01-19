# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Rackspace
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""
Created on August 22, 2012

@author: Justin Hammond, Rackspace Hosting
"""

import logging

import common
import core
import nvpquery

logger = logging.getLogger(__name__)


def requireuuid(fn):
    def wrapper(self):
        if not self.uuid:
            msg = "Missing UUID for verb (%s). Failing"
            logger.error(msg % fn.__name__)
            return None
        return fn(self)
    return wrapper


class NVPEntity(core.Entity):

    def __init__(self, connection):
        super(NVPEntity, self).__init__(connection)

    def ignore_cluster_majority(self, ignore):
        self.ignore_cluster_majority = ignore
        return self

    def tags(self, taglist):
        """Will set/update the tag list of the object.

        Arguments:
        tagList -- a list of dictionaries with the following format:
        {
            'tag':<some value>,  <--- is required
            'scope':<some value>
        }
        If a list is not given and only a dictionary is given it will put the
        dictionary in a list for you.
        """
        if not type(taglist) is list:
            taglist = [taglist]
        elif len(taglist) > 5:
            raise AttributeError("Tag list only supports up to 5 elements")
        self['tags'] = taglist
        return self

    def display_name(self, name):
        """Will set/update the display name of the object. By default if a
        display name is not given the generated UUID will be used as the
        display name.

        Arguments:
        name -- a string with max length of 40
        """
        if len(name) > 40:
            raise AttributeError("Display name is greater than 40 characters")
        self['display_name'] = name
        return self


class QOSQueue(NVPEntity):
    # All queue specific functionality has been implemented
    # TODO: it now needs to be tested
    def __init__(self, connection, uuid=None):
        super(QOSQueue, self).__init__(connection)
        self.uuid = uuid

    def dscp(self, value):
        """IP header DSCP value

        Arguments:
        value -- integer between 0 and 63
        """
        if value < 0 or value > 63:
            raise AttributeError("DSCP value out of range")
        self['dscp'] = value
        return self

    def maxbw_rate(self, rate):
        """Maximum bitrate for queue in kbps

        Arguments:
        rate -- positive integer
        """
        if rate < 0:
            raise AttributeError("Rate must be positive")
        self['max_bandwidth_rate'] = rate
        return self

    def minbw_rate(self, rate):
        """Minimum bitrate for queue in kbps

        Arguments:
        rate -- positive integer
        """
        if rate < 0:
            raise AttributeError("Rate must be positive")
        self['min_bandwidth_rate'] = rate
        return self

    def qos_marking(self, marking):
        """Will set the DSCP field.

        Arguments:
        marking -- string that can be 'trusted' or 'untrusted'
        """
        if marking != 'trusted' or marking != 'untrusted':
            raise AttributeError("Marking can be 'trusted' or 'untrusted'")
        self['qos_marking']
        return self

    def create(self):
        """Create (verb) will create the QoS queue"""
        uri = common.genuri('lqueue')
        return super(QOSQueue, self)._action('POST', uri)

    def query(self):
        """Returns the query object for the QoS queue"""
        uri = common.genuri('lqueue')
        queryobject = nvpquery.QOSQueueQuery(self.connection, uri)
        return queryobject

    def query_by_switch(self, switchuuid):
        """Returns the query object for all queues on all ports of the switch
        """
        uri = common.genuri('lswitch', switchuuid, 'lqueue')
        queryobject = nvpquery.QOSQueueQuery(self.connection, uri)
        return queryobject

    @requireuuid
    def update(self):
        """Update (verb) will update the QoS queue"""
        uri = common.genuri('lqueue', self.uuid)
        return super(QOSQueue, self)._action('PUT', uri)

    @requireuuid
    def read(self):
        """Read (verb) will read the QoS queue config"""
        uri = common.genuri('lqueue', self.uuid)
        return super(QOSQueue, self)._action('GET', uri)

    @requireuuid
    def delete(self):
        """Delete (verb) will delete the QoS queue"""
        uri = common.genuri('lqueue', self.uuid)
        return super(QOSQueue, self)._action('DELETE', uri)


class SecurityRule(dict):
    """Utility class for SecurityProfile's rules"""
    ethertype_map = {'ipv4': "IPv4", 'ipv6': "IPv6",
                     '4': "IPv4", '6': "IPv6"}

    def __init__(self, ethertype, ip_prefix=None, port_range_max=None,
                 port_range_min=None, profile_uuid=None, protocol=None):
        if isinstance(ethertype, basestring):
            ethertype = SecurityRule.ethertype_map.get(ethertype.lower())

        if ethertype != "IPv4" and ethertype != "IPv6":
            raise AttributeError('Ethertype must be one of '
                                 '4, 6, IPv4, or IPv6)')

        self['ethertype'] = ethertype

        # TODO(jkoelker) DRY this up
        if ip_prefix is not None:
            self.ip_prefix(ip_prefix)

        if port_range_max is not None:
            self.port_range_max(port_range_max)

        if port_range_min is not None:
            self.port_range_min(port_range_min)

        if profile_uuid is not None:
            self.profile_uuid(profile_uuid)

        if protocol is not None:
            self.protocol(protocol)

    def ip_prefix(self, prefix):
        self['ip_prefix'] = prefix
        return self

    def port_range_max(self, port_range):
        if port_range < 0 or port_range > 65535:
            raise AttributeError("Max port range is out of range")
        self['port_range_max'] = port_range
        return self

    def port_range_min(self, port_range):
        if port_range < 0 or port_range > 65535:
            raise AttributeError("Min port range is out of range")
        self['port_range_min'] = port_range
        return self

    def profile_uuid(self, uuid):
        self['profile_uuid'] = uuid
        return self

    def protocol(self, protid):
        if protid < 0 or protid > 255:
            raise AttributeError("IP protocol number out of range")
        self['protocol'] = protid
        return self


class SecurityProfile(NVPEntity):
    # All security profile specific functionality has been implemented
    # TODO: It now needs to be tested
    def __init__(self, connection, uuid=None):
        super(SecurityProfile, self).__init__(connection)
        self.uuid = uuid

    def _validate_rulelist(self, rulelist):
        if not isinstance(rulelist, list):
            rulelist = [rulelist]

        if not all([isinstance(rule, (SecurityRule, dict))
                    for rule in rulelist]):
            raise AttributeError("SecurityRule or dict objects required")

        return rulelist

    def port_egress_rules(self, rulelist):
        """Sets rules for outbound traffic. All outbound traffic not matching
        the specified rules will be dropped.

        Arguments:
        rulelist -- a list of SecurityRule objects
        If a single SecurityRule object is given it will be put in a list
        for you
        """
        rulelist = self._validate_rulelist(rulelist)
        self['logical_port_egress_rules'] = rulelist
        return self

    def port_ingress_rules(self, rulelist):
        """Sets rules for inbound traffic. All inbound traffic not matching
        the specified rules will be dropped.

        Arguments:
        rulelist -- a list of SecurityRule objects
        If a single SecurityRule object is given it will be put in a list
        for you
        """
        rulelist = self._validate_rulelist(rulelist)
        self['logical_port_ingress_rules'] = rulelist
        return self

    def create(self):
        """Create (verb) will create the security profile"""
        uri = common.genuri('security-profile')
        return super(SecurityProfile, self)._action('POST', uri)

    def query(self):
        """Returns the query object for the security profile"""
        uri = common.genuri('security-profile')
        queryobject = nvpquery.SecurityProfileQuery(self.connection, uri)
        return queryobject

    @requireuuid
    def update(self):
        """Update (verb) will update the security profile"""
        uri = common.genuri('security-profile', self.uuid)
        return super(SecurityProfile, self)._action('PUT', uri)

    @requireuuid
    def read(self):
        """Read (verb) will read the security profile config"""
        uri = common.genuri('security-profile', self.uuid)
        return super(SecurityProfile, self)._action('GET', uri)

    @requireuuid
    def delete(self):
        """Delete (verb) will delete the security profile"""
        uri = common.genuri('security-profile', self.uuid)
        return super(SecurityProfile, self)._action('DELETE', uri)


class TransportConnector(dict):
    GRE = 'GREConnector'
    STT = 'STTConnector'
    BRIDGE = 'BridgeConnector'
    SECGRE = 'IPsecGREConnector'
    SECSTT = 'IPsecSTTConnector'
    _valid_entries = [GRE, STT, BRIDGE, SECGRE, SECSTT]

    def __init__(self, tzone_uuid, connector_type):
        if connector_type not in TransportConnector._valid_entries:
            raise AttributeError("connector_type is invalid")
        self['tzone_uuid'] = tzone_uuid
        self['connector_type'] = connector_type


class TransportNode(NVPEntity):
    # All node specific functionality has been implemented
    # TODO: It now needs to be tested
    def __init__(self, connection, uuid=None):
        super(TransportNode, self).__init__(connection)
        self.uuid = uuid

    def admin_status_enabled(self, flag):
        """Will set the admin enabled status of the node"""
        self['admin_status_enabled'] = flag
        return self

    def credential(self, mgmt_credentials):
        """Will set the credential of the node

        Arguments:
        mgmt_credentials -- either MgmtAddrCredential, or
                            SecurityCertificateCredential string
        """
        self['credential'] = mgmt_credentials
        return self

    def integration_bridge(self, bridgeid):
        """Used to connect logical and transport networks"""
        if len(bridgeid) > 40:
            raise AttributeError("Bridge id must be <= 40 characters")
        self['intergration_bridge_id'] = bridgeid
        return self

    def rendezvous_client(self, flag):
        """Indicates if node management connections may be established
        via a rendezvous server"""
        self['mgmt_rendezvous_client'] = flag
        return self

    def rendezvous_server(self, flag):
        """indicates if node should act as rendezvous server"""
        self['mgmt_rendezvous_server'] = flag
        return self

    def transport_connectors(self, connector_list):
        """Will connect the node to transport zones with a given connector
        of the specified type.

        Arguments:
        connector_list -- a list of TransportConnector objects; if a single
                          object is given it will be put into a list for you
        """
        if not type(connector_list) is list:
            connector_list = [connector_list]

        if not all([isinstance(conn, (TransportConnector, dict))
                    for conn in connector_list]):
            raise AttributeError('TransportConnector or dict objects '
                                 'required')

        self['transport_connectors'] = connector_list
        return self

    def zone_forwarding(self, flag):
        """Indicates if node may be used to forward packets between
        transport zones."""
        self['zone_fowarding'] = flag
        return self

    def create(self):
        """Create (verb) will create the transport node"""
        uri = common.genuri('transport-node')
        return super(TransportNode, self)._action('POST', uri)

    def query(self):
        """Returns the query object for the transport node"""
        uri = common.genuri('transport-node')
        queryobject = nvpquery.TransportNodeQuery(self.connection, uri)
        return queryobject

    @requireuuid
    def status(self):
        """Will get the status of the transport node"""
        uri = common.genuri('transport-node', self.uuid, 'status')
        return super(TransportNode, self)._action('GET', uri)

    @requireuuid
    def update(self):
        """Update (verb) will update the transport node"""
        uri = common.genuri('transport-node', self.uuid)
        return super(TransportNode, self)._action('PUT', uri)

    @requireuuid
    def read(self):
        """Read (verb) will read the transport node config"""
        uri = common.genuri('transport-node', self.uuid)
        return super(TransportNode, self)._action('GET', uri)

    @requireuuid
    def delete(self):
        """Delete (verb) will delete the transport node"""
        uri = common.genuri('transport-node', self.uuid)
        return super(TransportNode, self)._action('DELETE', uri)


class GatewayService(NVPEntity):
    # TODO: Basic support requires entity specific features on creation
    # TODO: Add all entity specific features
    def __init__(self, connection, uuid=None):
        super(GatewayService, self).__init__(connection)
        self.uuid = uuid

    def create(self):
        """Create (verb) will create the Gateway Service"""
        uri = common.genuri('gateway-service')
        return super(GatewayService, self)._action('POST', uri)

    def query(self):
        """Returns the query object for the Gateway Service"""
        uri = common.genuri('gateway-service')
        queryobject = nvpquery.GatewayServiceQuery(self.connection, uri)
        return queryobject

    @requireuuid
    def update(self):
        """Update (verb) will update the Gateway Service"""
        uri = common.genuri('gateway-service', self.uuid)
        return super(GatewayService, self)._action('PUT', uri)

    @requireuuid
    def read(self):
        """Read (verb) will read the Gateway Service config"""
        uri = common.genuri('gateway-service', self.uuid)
        return super(GatewayService, self)._action('GET', uri)

    @requireuuid
    def delete(self):
        """Delete (verb) will delete the Gateway Service"""
        uri = common.genuri('gateway-service', self.uuid)
        return super(GatewayService, self)._action('DELETE', uri)


class TransportZone(NVPEntity):

    def __init__(self, connection, uuid=None):
        super(TransportZone, self).__init__(connection)
        self.uuid = uuid

    def create(self):
        """Create (verb) will create the transport zone"""
        uri = common.genuri('transport-zone')
        return super(TransportZone, self)._action('POST', uri)

    def query(self):
        """Returns the query object for the transport zone"""
        uri = common.genuri('transport-zone')
        queryobject = nvpquery.TransportZoneQuery(self.connection, uri)
        return queryobject

    @requireuuid
    def update(self):
        """Update (verb) will update the transport zone"""
        uri = common.genuri('transport-zone', self.uuid)
        return super(TransportZone, self)._action('PUT', uri)

    @requireuuid
    def read(self):
        """Read (verb) will read the transport zone config"""
        uri = common.genuri('transport-zone', self.uuid)
        return super(TransportZone, self)._action('GET', uri)

    @requireuuid
    def delete(self):
        """Delete (verb) will delete the transport zone"""
        uri = common.genuri('transport-zone', self.uuid)
        return super(TransportZone, self)._action('DELETE', uri)


class LSwitch(NVPEntity):

    def __init__(self, connection, uuid=None):
        super(LSwitch, self).__init__(connection)
        self.uuid = uuid

    def port_isolation_enabled(self, enabled):
        """Will set/update the port_isolation_enabled flag on the switch
        """
        self['port_isolation_enabled'] = enabled
        return self

    def transport_zone(self, zone_uuid, transport_type,
                       vlan_id=None, vxlan_id=None):
        """Sets/updates the transport zones that the switch is connected
        to. Expects zones to be a list of dicts with keys "zone_uuid" and
        "transport_type" set in each.
        """
        self["transport_zones"] = self.get("transport_zones") or []
        tz = dict(zone_uuid=zone_uuid, transport_type=transport_type)
        if vlan_id or vxlan_id:
            tz["binding_config"] = {}
            if vlan_id:
                vlan = dict(transport=vlan_id)
                tz["binding_config"]["vlan_translation"] = [vlan]
            if vxlan_id:
                vxlan = dict(transport=vxlan_id)
                tz["binding_config"]["vxlan_transport"] = [vxlan]
        self["transport_zones"].append(tz)
        return self

    def query(self):
        """Returns the query object for logical switches
        """
        queryobject = nvpquery.LSwitchQuery(self.connection,
                                            common.genuri('lswitch'))
        return queryobject

    def create(self):
        """Create (verb) will create the logical switch
        """
        return super(LSwitch, self)._action('POST', common.genuri('lswitch'))

    @requireuuid
    def delete(self):
        """Delete (verb) will delete the logical switch
        Requires a UUID set at the object.
        """
        uri = common.genuri('lswitch', self.uuid)
        return super(LSwitch, self)._action('DELETE', uri)

    @requireuuid
    def status(self):
        """Status (verb) will return the network status of the logical switch
        Requires a UUID set at the object.
        """
        uri = common.genuri('lswitch', self.uuid, 'status')
        return super(LSwitch, self)._action('GET', uri)

    @requireuuid
    def read(self):
        """Read (verb) will return the configuration of the logical switch
        Requires a UUID set at the object.
        """
        uri = common.genuri('lswitch', self.uuid)
        return super(LSwitch, self)._action('GET', uri)

    @requireuuid
    def update(self):
        """Update (verb) will update the logical switch
        Requires a UUID set at the object.
        """
        uri = common.genuri('lswitch', self.uuid)
        return super(LSwitch, self)._action('PUT', uri)


class LSwitchPort(NVPEntity):

    def __init__(self, connection, lswitch_uuid, uuid=None):
        super(LSwitchPort, self).__init__(connection)
        self.lswitch_uuid = lswitch_uuid
        self.uuid = uuid

    def admin_status_enabled(self, enabled):
        self['admin_status_enabled'] = enabled
        return self

    def attachment_patch(self, peer_uuid, lrouter_uuid=None):
        if not common.isuuid(peer_uuid):
            raise AttributeError("Peer Port UUID is invalid")
        if lrouter_uuid and not common.isuuid(lrouter_uuid):
            raise AttributeError("Logical Router UUID is invalid")
        pass

    def attachment_vif(self, vif_uuid, hypervisor=None):
        logger.info("Attaching VIF %s" % vif_uuid)
        self["vif_uuid"] = vif_uuid
        self["type"] = "VifAttachment"
        uri = common.genuri("lswitch", self.lswitch_uuid, "lport", self.uuid,
                            "attachment")
        return super(LSwitchPort, self)._action('PUT', uri)

    def attachment_extended_network_bridge(self, tnode_uuid, bridgeid,
                                           vlan=None):
        pass

    def attachment_mdi(self, mdiservice, interconnectid):
        pass

    def attachment_l2gateway(self, gateway_uuid, vlan=None):
        pass

    def allowed_address_pairs(self, address_pair_list):
        """Will set/update the address pair list of the object.

        Arguments:
        addressPairList -- a list of dictionaries with the following format:
        {
            'mac':<some value>,  <--- is required
            'ip':<some value>
        }
        If a list is not given and only a dictionary is given it will put the
        dictionary in a list for you.
        """
        if not type(address_pair_list) is list:
            address_pair_list = [address_pair_list]
        self['allowed_address_pairs'] = address_pair_list
        return self

    def mirror_targets(self, mirrorlist):
        """Will set/update the mirror target list of the object.

        Arguments:
        mirror_targets -- a list of IPs that can have up to 3 items
        """
        if not type(mirrorlist) is list:
            mirrorlist = [mirrorlist]
        elif len(mirrorlist) > 3:
            raise AttributeError("Mirror list has greater than 3 items")
        self['mirror_targets'] = mirrorlist
        return self

    def portno(self, portnum):
        """Will set/update the port number of the object.

        Arguments:
        portnum -- a integer between 1 and 1000000 inclusive
        """
        if portnum < 1 or portnum > 1000000:
            raise AttributeError("Port number value out of range (1,1000000)")
        self['portno'] = portnum
        return self

    def qosuuid(self, uuid):
        """Will set/update the QoS queue UUID of the object.

        Arguments:
        uuid -- a string or None, if None is used 'null' will be sent and the
                QoS UUID of the object will be unset
        """
        if uuid is None:
            uuid = 'null'
        elif not common.isuuid(uuid):
            raise AttributeError("UUID is invalid")
        self['queue_uuid'] = uuid
        return self

    def security_profiles(self, uuidlist):
        """Will set/update the security profile list of of the object.

        Arguments:
        uuidlist -- A list of strings in UUID format
        If a list is not given and only a single UUID string is given it will
        put the string in a list for you.
        """
        if not type(uuidlist) is list:
            uuidlist = [uuidlist]
        if False in map(common.isuuid, uuidlist):
            raise AttributeError("One or more UUIDs are invalid")
        self['security_profiles'] = uuidlist
        return self

    def create(self):
        """Create (verb) will create the logical port on the switch"""
        uri = common.genuri('lswitch', self.lswitch_uuid, 'lport')
        return super(LSwitchPort, self)._action("POST", uri)

    def query(self):
        """Returns the query object for logical switch ports
        """
        uri = common.genuri('lswitch', self.lswitch_uuid, 'lport')
        queryobject = nvpquery.LSwitchPortQuery(self.connection, uri)
        return queryobject

    @requireuuid
    def read(self):
        """Read (verb) will read the logical port's configuration"""
        uri = common.genuri('lswitch', self.lswitch_uuid, 'lport', self.uuid)
        return super(LSwitchPort, self)._action("GET", uri)

    @requireuuid
    def statistics(self):
        """statistics (verb) will return the port's stats"""
        uri = common.genuri('lswitch', self.lswitch_uuid, 'lport', self.uuid,
                            'statistic')
        return super(LSwitchPort, self)._action("GET", uri)

    @requireuuid
    def clear_statistics(self):
        """clear_statistics (verb) will clear the port's stats"""
        uri = common.genuri('lswitch', self.lswitch_uuid, 'lport', self.uuid,
                            'statistic')
        return super(LSwitchPort, self)._action("DELETE", uri)

    @requireuuid
    def status(self):
        """Status (verb) will return the logical port's status"""
        uri = common.genuri('lswitch', self.lswitch_uuid, 'lport', self.uuid,
                            'status')
        return super(LSwitchPort, self)._action("GET", uri)

    @requireuuid
    def delete(self):
        """Delete (verb) will delete the logical port.
        Requires a UUID set at the object"""
        uri = common.genuri('lswitch', self.lswitch_uuid, 'lport', self.uuid)
        return super(LSwitchPort, self)._action("DELETE", uri)

    @requireuuid
    def update(self):
        """Update (verb) will update the logical switch port
        Requires a UUID set at the object.
        """
        uri = common.genuri('lswitch', self.lswitch_uuid, 'lport', self.uuid)
        return super(LSwitchPort, self)._action('PUT', uri)
