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
Created: August 29, 2012

@author: Justin Hammond, Rackspace Hosting
"""

import tests.base


class TestTransportZone(tests.base.IntegrationTestBase):

    def setUp(self):
        super(TestTransportZone, self).setUp()
        self.zone = self.nvp.zone().create()

    def tearDown(self):
        if self.zone:
            self.nvp.zone(self.zone).delete()

    def test_transportzone_create(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_transportzone_read(self):
        zone_info = self.nvp.zone(self.zone).read()
        self.assertTrue(zone_info['uuid'] == self.zone['uuid'],
                        "Zone uuid should be the same UUID as stored")

    def test_transportzone_delete(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_transportzone_query(self):
        query = self.nvp.zone().query()
        query_results = query.uuid(self.zone['uuid']).results()
        self.assertTrue(query_results['result_count'] == 1,
                        "Query on UUID should return single result")

    def test_transportzone_update(self):
        current_name = self.zone['display_name']
        new_name = "test%s" % current_name
        zone_object = self.nvp.zone(self.zone)
        changed_zone = zone_object.display_name(new_name).update()
        self.assertTrue(changed_zone['display_name'] == new_name and
                        self.zone['display_name'] == current_name and
                        changed_zone['uuid'] == self.zone['uuid'],
                        "Data on same UUID should be different post update")
