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
Created: August 30, 2012

@author: Justin Hammond, Rackspace Hosting
"""

import tests.base


class TestTransportNode(tests.base.IntegrationTestBase):

    def setUp(self):
        super(TestTransportNode, self).setUp()
        self.tnode = self.nvp.transportnode().create()

    def tearDown(self):
        if self.tnode:
            self.nvp.transportnode(self.tnode).delete()

    def test_tnode_create(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_tnode_read(self):
        qos_info = self.nvp.transportnode(self.tnode).read()
        self.assertTrue(qos_info['uuid'] == self.tnode['uuid'],
                        "qos uuid should be the same UUID as stored")

    def test_tnode_delete(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_tnode_query(self):
        query = self.nvp.transportnode().query()
        query_results = query.uuid(self.tnode['uuid']).results()
        self.assertTrue(query_results['result_count'] == 1,
                        "Query on UUID should return single result")

    def test_tnode_update(self):
        current_name = self.tnode['display_name']
        new_name = "test%s" % current_name
        tnode_object = self.nvp.transportnode(self.tnode)
        changed_tnode = tnode_object.display_name(new_name).update()
        self.assertTrue(changed_tnode['display_name'] == new_name and
                        self.tnode['display_name'] == current_name and
                        changed_tnode['uuid'] == self.tnode['uuid'],
                        "Data on same UUID should be different post update")
