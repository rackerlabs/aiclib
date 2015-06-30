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
Created on August 21, 2012

@author: Justin Hammond, Rackspace Hosting
"""

import calendar
import logging
import uuid

logger = logging.getLogger(__name__)

_version = 'ws.v1'
stringoperators = ['=', '!=', '~', '!~']
booleanoperators = ['=', '!=', '<', '>', '<=', '>=']


def is_stringop(stringop):
    return stringop in stringoperators


def is_booleanop(boolop):
    return boolop in booleanoperators


def genuri(*args):
    uri = "/%s/%s" % (_version, "/".join(args))
    return uri


def dttounix(date_time):
    unixtime = calendar.timegm(date_time.utctimetuple())
    return unixtime


def isuuid(the_uuid):
    try:
        uuid.UUID(the_uuid, version=4)
    except (ValueError, AttributeError):
        return False
    return True
