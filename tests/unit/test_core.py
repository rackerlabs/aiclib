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

import socket
import aiclib
import tests.base as test_base

from tests.unit import fixtures


class ConnectionTestCase(test_base.UnitTestBase):
    def setUp(self):
        super(ConnectionTestCase, self).setUp()

        self.connection = aiclib.nvp.Connection(
            "https://localhost", username='fakeuser', password='fakepass',
            retries=2, backoff=0)

    def test_connection_retries_unauthorized(self):
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie'})
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie2'})

        self._add_response(
            '/ws.v1/lswitch', status=200, body=fixtures.LSWITCH_Q,
            headers={"content-type": "application/json",
                     "content-length": str(len(fixtures.LSWITCH_Q))})
        self._add_response(
            '/ws.v1/lswitch', status=401, reason='Unauthorized')
        self._add_response(
            '/ws.v1/lswitch', status=200, body=fixtures.LSWITCH_Q,
            headers={"content-type": "application/json",
                     "content-length": str(len(fixtures.LSWITCH_Q))})

        # First call, should succeed
        response = self.connection.lswitch().query().results()
        # Second call, should be unauthorized, reauth, and then succeed.
        response2 = self.connection.lswitch().query().results()

        # sanity check response object
        self.assertEqual(response['results'][0]['display_name'],
                         'lswitch1')
        self.assertEqual(response, response2)

        # 2x auth and 3x lswitch query
        self.assertEqual(len(self._calls), 5)

    def test_connection_reauth_uses_new_cookie(self):
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie'})
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie2'})

        self._add_response(
            '/ws.v1/lswitch', status=200, body=fixtures.LSWITCH_Q,
            headers={"content-type": "application/json",
                     "content-length": str(len(fixtures.LSWITCH_Q))})
        self._add_response(
            '/ws.v1/lswitch', status=401, reason='Unauthorized')
        self._add_response(
            '/ws.v1/lswitch', status=200, body=fixtures.LSWITCH_Q,
            headers={"content-type": "application/json",
                     "content-length": str(len(fixtures.LSWITCH_Q))})

        # First call, should succeed
        self.connection.lswitch().query().results()
        # Second call, should be unauthorized, reauth, and then succeed.
        self.connection.lswitch().query().results()

        # Assert the value of the Cookie is set correctly - first 2
        # lswitch calls use the first cookie, the second one 401s,
        # reauth happens, and the 3rd call uses the new cookie.
        self.assertEqual(self._calls[1][4]['Cookie'], 'fakecookie')
        self.assertEqual(self._calls[2][4]['Cookie'], 'fakecookie')
        self.assertEqual(self._calls[4][4]['Cookie'], 'fakecookie2')

    def test_connection_retry_exhaustion_raises(self):
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie'})
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie'})
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie'})

        self._add_response(
            '/ws.v1/lswitch', status=401, reason='Unauthorized')
        self._add_response(
            '/ws.v1/lswitch', status=401, reason='Unauthorized')

        msg = 'Max retries reached'
        with self.assertRaises(aiclib.core.AICException) as e:
            self.connection.connection.request(
                'GET', '/ws.v1/lswitch', retries=1)

        self.assertEqual(e.exception.code, 408)
        self.assertTrue(msg in e.exception.message)

    def test_connection_redirect_once(self):
        """Test redirecting succeeds."""
        # we expect to query lswitches (and auth once), return 401 on the
        # second lswitch query (triggering a re-auth), and finally succeed
        # the third call.
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie'})
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie2'})

        self._add_response(
            '/ws.v1/lswitch', status=301,
            headers={'location': 'https://newhost:443/ws.v1/lswitch'})
        self._add_response(
            '/ws.v1/lswitch', status=200, body=fixtures.LSWITCH_Q,
            headers={"content-type": "application/json",
                     "content-length": str(len(fixtures.LSWITCH_Q))})

        response = self.connection.lswitch().query().results()
        self.assertEqual(response['results'][0]['display_name'],
                         'lswitch1')

        # assert that after redirect we actually re-auth and use the new cookie
        self.assertEqual(self._calls[1][4]['Cookie'], 'fakecookie')
        self.assertEqual(self._calls[3][4]['Cookie'], 'fakecookie2')

        # assert that we are making redirected requests against the new host
        self.assertEqual(self._calls[0][0].host, 'localhost')
        self.assertEqual(self._calls[1][0].host, 'localhost')
        self.assertEqual(self._calls[2][0].host, 'newhost')
        self.assertEqual(self._calls[3][0].host, 'newhost')

    def test_connection_redirect_multiple(self):
        """Test redirecting multiple times succeeds."""
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie'})
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie2'})
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie3'})

        self._add_response(
            '/ws.v1/lswitch', status=301,
            headers={'location': 'https://newhost:443/ws.v1/lswitch'})
        self._add_response(
            '/ws.v1/lswitch', status=301,
            headers={'location': 'https://anotherhost:443/ws.v1/lswitch'})
        self._add_response(
            '/ws.v1/lswitch', status=200, body=fixtures.LSWITCH_Q,
            headers={"content-type": "application/json",
                     "content-length": str(len(fixtures.LSWITCH_Q))})

        response = self.connection.lswitch().query().results()
        self.assertEqual(response['results'][0]['display_name'],
                         'lswitch1')

        # assert that after redirect we actually re-auth and use
        # the new cookie
        self.assertEqual(self._calls[1][4]['Cookie'], 'fakecookie')
        self.assertEqual(self._calls[3][4]['Cookie'], 'fakecookie2')
        self.assertEqual(self._calls[5][4]['Cookie'], 'fakecookie3')

        # assert that we are making redirected requests against
        # the new host
        self.assertEqual(self._calls[0][0].host, 'localhost')
        self.assertEqual(self._calls[1][0].host, 'localhost')
        self.assertEqual(self._calls[2][0].host, 'newhost')
        self.assertEqual(self._calls[3][0].host, 'newhost')
        self.assertEqual(self._calls[4][0].host, 'anotherhost')
        self.assertEqual(self._calls[5][0].host, 'anotherhost')

    def test_connection_redirect_exhaustion_raises(self):
        """Test redirecting 'retries' times raises."""
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie'})
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie2'})
        self._add_response(
            '/ws.v1/login', status=200, headers={'set-cookie': 'fakecookie3'})

        self._add_response(
            '/ws.v1/lswitch', status=301,
            headers={'location': 'https://newhost:443/ws.v1/lswitch'})
        self._add_response(
            '/ws.v1/lswitch', status=301,
            headers={'location': 'https://anotherhost:443/ws.v1/lswitch'})
        self._add_response(
            '/ws.v1/lswitch', status=200, body=fixtures.LSWITCH_Q,
            headers={"content-type": "application/json",
                     "content-length": str(len(fixtures.LSWITCH_Q))})

        msg = 'Max retries reached'
        with self.assertRaises(aiclib.core.AICException) as e:
            self.connection.connection.request('GET', '/ws.v1/lswitch',
                                               retries=0)

        self.assertEqual(e.exception.code, 408)
        self.assertTrue(msg in e.exception.message)

    def test_connection_tcp_options(self):
        """Tests the TCP options set on the connection.
        In particular we are looking for so_keepalive.
        """
        conn = self.connection.conn._get_conn()
        socket_options = conn.socket_options

        #
        # TCP socket options are set in a list of tuples, such as:
        # [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1), (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)]
        #
        self.assertTrue((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) in socket_options, 'Did not find SO_KEEPALIVE in tcp_options')

        self.assertTrue((socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) in socket_options, 'Did not find TCP_NODELAY in tcp_options')
