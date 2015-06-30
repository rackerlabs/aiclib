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


class TestQOS(tests.base.IntegrationTestBase):

    def setUp(self):
        super(TestQOS, self).setUp()
        self.qos = self.nvp.qos().create()

    def tearDown(self):
        if self.qos:
            self.nvp.qos(self.qos).delete()

    def test_qos_create(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_qos_read(self):
        qos_info = self.nvp.qos(self.qos).read()
        self.assertTrue(qos_info['uuid'] == self.qos['uuid'],
                        "qos uuid should be the same UUID as stored")

    def test_qos_delete(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_qos_query(self):
        query = self.nvp.qos().query()
        query_results = query.uuid(self.qos['uuid']).results()
        self.assertTrue(query_results['result_count'] == 1,
                        "Query on UUID should return single result")

    def test_qos_update(self):
        current_name = self.qos['display_name']
        new_name = "test%s" % current_name
        qos_object = self.nvp.qos(self.qos)
        changed_qos = qos_object.display_name(new_name).update()
        self.assertTrue(changed_qos['display_name'] == new_name and
                        self.qos['display_name'] == current_name and
                        changed_qos['uuid'] == self.qos['uuid'],
                        "Data on same UUID should be different post update")
