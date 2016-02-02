# Copyright 2015 Rackspace Hosting Inc.
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
Created on August 17, 2012

@author: Justin Hammond, Rackspace Hosting
"""

import errno
import json
import logging
import socket
import time

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import urllib3
import urlparse

import common
import nvp


logger = logging.getLogger(__name__)


class CoreLib(object):

    def __init__(self, uri, poolmanager=None, username='admin',
                 password='admin', **kwargs):
        """Constructor for the AICLib object.

        Arguments:
        uri -- the address of the nvp controller including scheme (required)

        Keyword arguments:
        poolmanager -- a pool manager provided by urlib3 (default None)
        username -- the username to log into the nvp controller
        password -- the password to log into the nvp controller
        """
        retries = kwargs.get("retries", 3)
        if poolmanager is None:
            self.conn = urllib3.connection_from_url(uri, retries=retries)

        else:
            self.conn = poolmanager.connection_from_url(uri, retries=retries)

        self.connection = Connection(connection=self.conn,
                                     username=username,
                                     password=password,
                                     **kwargs)

    def _action(self, entity, method, resource):
        if entity is None:
            return

        logger.info("(%s @ %s): %s" % (method, resource,
                                       entity._unroll()))
        try:
            r = self.connection.request(method, resource,
                                        body=entity._unroll())
        except socket.error, v:
            errorcode = v[0]

            if errorcode == errno.ECONNREFUSED:
                logger.error("Connection refused")

            raise urllib3.exceptions.HTTPError("Connection refused")
        return r


class Entity(dict):

    def __init__(self, connection):
        self.connection = connection

    def _action(self, method, resource):
        """This is the ancestor method that all 'verbs' must call to perform
        an action.
        """
        return self.connection._action(self, method, resource)

    def _unroll(self):
        return self


class Query(object):

    def __init__(self, connection, resource):
        self.connection = connection
        self.query = {}
        self.resource = resource

    def _query(self, method):
        return self.connection._action(self, method, self.resource)

    def _unroll(self):
        return self.query


class Connection(object):
    _encode_url_methods = set(['DELETE', 'GET', 'HEAD', 'OPTIONS'])
    _encode_body_methods = set(['PATCH', 'POST', 'PUT', 'TRACE'])

    def __init__(self, username, password, connection=None, timeout=10,
                 retries=5, backoff=2):
        self._conn = connection
        self.authenticated = False
        self.username = username
        self.password = password
        self.retries = retries
        self.timeout = timeout
        self.backoff = backoff
        self._headers = {}
        self.generationnumber = 0
        self.authkey = ''

    @property
    def connection(self):
        if(not self.authenticated and
           not self._login(self.username, self.password)):
                logger.error("Authorization failed.")
                raise IOError('401', 'Unauthorized')
        return self._conn

    def _login(self, username, password, uri=None):
        fields = {'username': username, 'password': password}
        if not uri:
            uri = common.genuri('login')
        r = self._conn.request_encode_body('POST', uri,
                                           fields=fields, timeout=self.timeout,
                                           encode_multipart=False,
                                           headers=None, retries=0)
        if self._iserror(r):
            return False
        else:
            self.authkey = r.headers['set-cookie']
        self.authenticated = True
        return True

    @property
    def headers(self):
        self._headers = {
            'Cookie': self.authkey,
            'Content-Type': 'application/json',
            'X-Nvp-Wait-For-Config-Generation': self.generationnumber,
        }
        return self._headers

    def _prep_body_and_url(self, method, url, body, is_url_prepared,
                           is_body_prepared):
        new_body = None
        new_url = url
        if body:
            if method in self._encode_url_methods and not is_url_prepared:
                params = urlencode(body, doseq=True)
                new_url = "%s?%s" % (url, params)
            else:
                if not is_body_prepared:
                    body = json.dumps(body)
                new_body = body
        else:
            if method in ("PUT", "POST"):
                new_body = '{}'
        return new_body, new_url

    def request(self, method, url, generationnumber=0, body=None,
                retries=None, backoff=None, is_url_prepared=False,
                is_body_prepared=False):

        if not self.authenticated:
            self._login(self.username, self.password)

        if retries is None:
            retries = self.retries

        if backoff is None:
            backoff = self.backoff

        if retries < 0:
            raise AICException(408, 'Max retries reached')

        self.generationnumber = generationnumber
        open_args = [method]
        open_kwargs = {'retries': False, 'redirect': False,
                       'timeout': self.timeout, 'headers': self.headers}

        body, url = self._prep_body_and_url(method, url, body,
                                            is_url_prepared,
                                            is_body_prepared)
        open_kwargs['body'] = body
        open_args.append(url)

        try:
            r = self.connection.urlopen(*open_args, **open_kwargs)

            if self._iserror(r):
                try:
                    self._handle_error(r)
                except:
                    logger.error("Unhandled error: reraising.")
                    raise

            if self._is_redirect(r):
                new_host = urlparse.urlparse(
                    r.headers['location']).netloc.split(':')[0]
                self._conn = urllib3.connectionpool.HTTPSConnectionPool(
                    host=new_host, port=443)
                self.authenticated = False
                logger.info("Request redirect %s (%s) to %s"
                            % (r.status, r.reason, new_host))

        except (urllib3.exceptions.TimeoutError, nvp.RequestTimeout):
            logger.exception(' '.join(('Timeout talking to NVP.',
                                       'Will retry %s more times.')),
                             retries - 1)

        if not self._iserror(r) and not self._is_redirect(r):
            return r

        # NOTE(jkoelker) Lets be nice(er) to NVP with an exponential
        #                backoff.
        if not self._is_redirect(r):
            time.sleep(backoff)
            backoff = backoff ** 2

        retries = retries - 1
        return self.request(method, url, generationnumber=generationnumber,
                            body=body, retries=retries, backoff=backoff,
                            is_url_prepared=True, is_body_prepared=True)

    def _handle_headers(self, resp):
        return

    def _iserror(self, resp):
        if (resp.status >= 300 and not self._is_redirect(resp)):
            logger.info("Request error %s (%s)" % (resp.status, resp.reason))
            return True
        logger.info("Request success %s (%s)" % (resp.status, resp.reason))
        return False

    def _is_redirect(self, resp):
        if resp.status in resp.REDIRECT_STATUSES:
            logger.debug("Redirect detected: %s" % resp.status)
            return True
        return False

    def _handle_error(self, resp):
        logger.info("Received error %s (%s)" % (resp.status, resp.reason))
        comment = "%s: %s" % (resp.reason, resp.data)

        if resp.status == 400:
            logger.error("Bad request")
            raise AICException(400, comment)

        elif resp.status == 401:
            logger.info("Authorization expired; renewing")
            self.authenticated = False
            authstatus = self._login(self.username, self.password)

            if not authstatus:
                logger.error("Re-authorization failed.")
                raise AICException(401, 'Unauthorized')

        elif resp.status == 403:
            logger.error("Access forbidden")
            raise AICException(403, comment)

        elif resp.status == 404:
            logger.error("Resource not found")
            raise AICException(404, comment)

        elif resp.status == 409:
            logger.error("Conflicting configuration")
            raise AICException(409, comment)

        elif resp.status == 500:
            logger.error("Internal server error")
            raise AICException(500, comment)

        elif resp.status == 503:
            logger.error("Service unavailable")
            raise AICException(503, comment)


class AICException(Exception):

    def __init__(self, error_code, message, **kwargs):
        super(AICException, self).__init__(kwargs)
        self.code = error_code
        self.message = message
