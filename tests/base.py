# Copyright 2015 Rackspace
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

import os

import aiclib
import tests

import mock

import collections
import urllib3
import io

try:
    from urllib import parse as urlparse
except ImportError:
    from urlparse import urlparse


def _fake_response(status, reason, body, headers):
    """Generate a fake urllib3 response object."""
    return urllib3.HTTPResponse(
            status=status,
            reason=reason,
            body=io.BytesIO(body) if body else io.BytesIO(),
            headers=headers,
            preload_content=False
    )


class IntegrationTestBase(tests.TestCase):

    def setUp(self):
        default = "localhost"
        default_user = "admin"
        default_password = "password"

        self.urls = os.getenv('AICLIB_NVP_URL', default).split(',')
        self.username = os.getenv('AICLIB_NVP_USERNAME', default_user)
        self.password = os.getenv('AICLIB_NVP_PASSWORD', default_password)

        self.nvp = aiclib.nvp.Connection(self.urls[0],
                                         username=self.username,
                                         password=self.password)


class UnitTestBase(tests.TestCase):
    def setUp(self):
        super(UnitTestBase, self).setUp()
        self._responses = collections.defaultdict(list)
        self._calls = []

        # Mock out urllib3, allowing us to specify return values for
        # particular urls in our tests.
        def _urlopen(pool, method, url, body=None, headers=None, **kwargs):
            self._calls.append(
                (pool, method, url, body, headers.copy(), kwargs.copy()))
            return self._get_response(url)

        target = 'urllib3.connectionpool.HTTPConnectionPool.urlopen'
        self._patcher = mock.patch(target, _urlopen)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

    def _add_response(self, url, status=200, reason=None,
                      body=None, headers=None):
        path = urlparse(url).path
        self._responses[path].append(_fake_response(
            status, reason, body, headers))

    def _get_response(self, url):
        response = self._responses.get(urlparse(url).path, [])
        if not response:
            raise Exception("No mock response added for %s" % (url))
        return response.pop(0)
