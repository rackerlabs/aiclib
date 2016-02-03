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
Created: August 27, 2012

@author: Justin Hammond, Rackspace Hosting
"""

import aiclib

import tests.base

class TestConnectionRedirect(tests.base.IntegrationTestBase):

    def setUp(self):
        super(TestConnectionRedirect, self).setUp()

        if len(self.urls) < 2:
            self.skipTest('Addition URLs required for redirection test.')

        self.nvp2 = aiclib.nvp.Connection(self.urls[1],
                                         username=self.username,
                                         password=self.password)

    def tearDown(self):
        if hasattr(self, 'switch'):
            self.nvp.lswitch(self.switch).delete()

    def test_redirect(self):

        # assert we are pointed at 2 different controllers
        self.assertNotEqual(self.nvp.connection._conn.host,
                            self.nvp2.connection._conn.host)

        # create a switch, and query it from both controllers
        self.switch = self.nvp.lswitch().create()
        query1 = self.nvp.lswitch().query()
        results1 = query1.uuid(self.switch['uuid']).results()
        query2 = self.nvp2.lswitch().query()
        results2 = query2.uuid(self.switch['uuid']).results()

        # assert that both connections are now pointed at the same
        # host
        self.assertEqual(self.nvp.connection._conn.host,
                         self.nvp2.connection._conn.host)
        self.assertEqual(results1, results2)


