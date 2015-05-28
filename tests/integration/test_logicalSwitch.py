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

import tests.base


class TestLogicalSwitch(tests.base.IntegrationTestBase):

    def setUp(self):
        super(TestLogicalSwitch, self).setUp()
        self.switch = self.nvp.lswitch().create()

    def tearDown(self):
        if self.switch:
            self.nvp.lswitch(self.switch).delete()

    def test_switch_create(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_switch_delete(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_switch_read(self):
        switch_info = self.nvp.lswitch(self.switch).read()
        self.assertTrue(switch_info['type'] == 'LogicalSwitchConfig',
                        "Switch info should be the correct type of JSON")

    def test_switch_status(self):
        switch_status = self.nvp.lswitch(self.switch).status()
        self.assertTrue(switch_status['type'] == 'LogicalSwitchStatus',
                        "Switch status should be the correct type of JSON")

    def test_switch_query(self):
        query = self.nvp.lswitch().query()
        query_results = query.uuid(self.switch['uuid']).results()
        self.assertTrue(query_results['result_count'] == 1,
                        "Query on UUID should return single result")

    def test_switch_update(self):
        current_name = self.switch['display_name']
        new_name = "test%s" % current_name
        switch_object = self.nvp.lswitch(self.switch)
        changed_switch = switch_object.display_name(new_name).update()
        self.assertTrue(changed_switch['display_name'] == new_name and
                        self.switch['display_name'] == current_name and
                        changed_switch['uuid'] == self.switch['uuid'],
                        "Data on same UUID should be different post update")
