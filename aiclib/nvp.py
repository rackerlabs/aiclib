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
Created on August 23, 2012

@author: Justin Hammond, Rackspace Hosting
"""

import json
import logging
import time

import common
import core
import nvpentity

logger = logging.getLogger(__name__)
_version = 'ws.v1'


def grab_uuid_of_type(text_or_dict, nvptype):
    if not type(text_or_dict) is dict:
        return text_or_dict
    errormsg = "Missing key (%s) from dictionary when expected."
    typeerror = "Incorrect type (%s); expected %s"
    if 'uuid' not in text_or_dict:
        logger.error(errormsg % "uuid")
        raise TypeError(errormsg % "uuid")
    if nvptype and 'type' not in text_or_dict:
        logger.error(errormsg % "type")
        raise TypeError(errormsg % "type")
        if text_or_dict['type'] != nvptype:
            logger.error(typeerror % (text_or_dict['type'], nvptype))
            raise TypeError(typeerror % (text_or_dict['type'], nvptype))
    return text_or_dict['uuid']


class Connection(core.CoreLib):
    def nvp_function(self):
        entity = NVPFunction(self)
        return entity

    def lswitch(self, uuid=None):
        uuidvalue = grab_uuid_of_type(uuid, "LogicalSwitchConfig")
        entity = nvpentity.LSwitch(self, uuid=uuidvalue)
        return entity

    def qos(self, uuid=None):
        uuidvalue = grab_uuid_of_type(uuid, None)
        entity = nvpentity.QOSQueue(self, uuid=uuidvalue)
        return entity

    def securityrule(self, ethertype, **fields):
        entity = nvpentity.SecurityRule(ethertype, **fields)
        return entity

    def securityprofile(self, uuid=None):
        uuidvalue = grab_uuid_of_type(uuid, None)
        entity = nvpentity.SecurityProfile(self, uuid=uuidvalue)
        return entity

    def lrouter(self, uuid=None):
        uuidvalue = grab_uuid_of_type(uuid, None)
        entity = nvpentity.LRouter(self, uuid=uuidvalue)
        return entity

    def transportconnector(self, uuid, connector_type):
        uuidvalue = grab_uuid_of_type(uuid, None)
        entity = nvpentity.TransportConnector(uuidvalue, connector_type)
        return entity

    def transportnode(self, uuid=None):
        uuidvalue = grab_uuid_of_type(uuid, None)
        entity = nvpentity.TransportNode(self, uuid=uuidvalue)
        return entity

    def gatewayservice(self, uuid=None):
        uuidvalue = grab_uuid_of_type(uuid, None)
        entity = nvpentity.GatewayService(self, uuid=uuidvalue)
        return entity

    def zone(self, uuid=None):
        uuidvalue = grab_uuid_of_type(uuid, None)
        entity = nvpentity.TransportZone(self, uuid=uuidvalue)
        return entity

    def lswitch_port(self, lswitch_uuid, uuid=None):
        """Will create an Logical Switch port on the passed Logical switch
        or passed UUID of a Logical switch"""
        lswitch_uuid_value = grab_uuid_of_type(lswitch_uuid,
                                               "LogicalSwitchConfig")
        lport_uuid_value = grab_uuid_of_type(uuid,
                                             "LogicalSwitchPortConfig")
        entity = nvpentity.LSwitchPort(self, lswitch_uuid_value,
                                       lport_uuid_value)
        return entity

    def handle_status_code(self, code, iserror=False, message=None):
        exception = None

        if code == 400 or code == 500:
            exception = NVPException

        elif code == 403:
            exception = Forbidden

        elif code == 404:
            exception = ResourceNotFound

        elif code == 408:
            exception = RequestTimeout

        elif code == 409:
            exception = Conflict

        elif code == 503:
            exception = ServiceUnavailable

        elif iserror:
            exception = NVPException
            message = "Unhandled error occurred"

        if exception is not None:
            raise exception(message)

    def _action(self, entity, method, resource):
        """Will inject generation ID into the JSON result object if it exists
        """
        # Changes to get the elapsed time
        starttime = time.time()
        try:
            r = super(Connection, self)._action(entity, method, resource)
        except core.AICException as e:
            logger.exception('AICException')
            self.handle_status_code(e.code, iserror=True, message=e.message)
        endtime = time.time() - starttime
        logger.info("(%s @ %s):%s:Elapsed time %.3f" % (method,
                                                        resource,
                                                        entity._unroll(),
                                                        endtime))
        self.handle_status_code(r.status)
        responselength = 0
        generationid = None

        if 'x-nvp-config-generation' in r.headers:
            generationid = r.getheader('x-nvp-config-generation')

        if 'content-length' in r.headers:
            responselength = int(r.getheader('content-length'))

        if responselength > 0:
            if r.getheader('content-type') == 'application/json':
                jsonreturn = json.loads(r.data)
                if generationid:
                    jsonreturn['_generationid'] = generationid
                if r.status:
                    jsonreturn['_nvpstatus'] = r.status
                return jsonreturn

            else:
                return r.data
        return


class NVPFunction(core.Entity):

    def __init__(self, connection):
        super(NVPFunction, self).__init__(connection)

    def logout(self):
        uri = common.genuri("logout")
        return super(NVPFunction, self)._action('GET', uri)

    def get_method_uris(self):
        uri = common.genuri("doc", "method")
        return super(NVPFunction, self)._action('GET', uri)

    def read_method(self, method_name):
        uri = common.genuri("doc", "method", method_name)
        return super(NVPFunction, self)._action('GET', uri)

    def get_schemas(self):
        uri = common.genuri("schema")
        return super(NVPFunction, self)._action('GET', uri)

    def read_schema(self, schema_name):
        uri = common.genuri("schema", schema_name)
        return super(NVPFunction, self)._action('GET', uri)


class NVPException(Exception):
    """This Exception class was created to duplicate the exception resolution
    available in legacy NvpApiClient.
    """
    message = "An unknown exception occurred."

    def __init__(self, *args):
        self._error_string = "%s %s" % (self.message, '\n'.join(args))

    def __str__(self):
        return self._error_string


class UnauthorizedRequest(NVPException):
    message = "Server denied session's authentication credentials."


class BadRequest(NVPException):
    message = "Server returned bad request"


class ServerError(NVPException):
    message = "Server returned bad request"


class ResourceNotFound(NVPException):
    message = "An entity referenced in the request was not found."


class Conflict(NVPException):
    message = "Request conflicts with configuration on a different entity."


class ServiceUnavailable(NVPException):
    message = ("Request could not be completed because the associated "
               "resource could not be reached")


class Forbidden(NVPException):
    message = "The request is forbidden from access the referenced resource"


class RequestTimeout(NVPException):
    message = "The request has timed out."
