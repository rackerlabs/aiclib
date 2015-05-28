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


class TestSecurityProfile(tests.base.IntegrationTestBase):

    def setUp(self):
        super(TestSecurityProfile, self).setUp()
        self.secprofile = self.nvp.securityprofile().create()

    def tearDown(self):
        if self.secprofile:
            self.nvp.securityprofile(self.secprofile).delete()

    def test_secprofile_create(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_secprofile_read(self):
        secprofile_info = self.nvp.securityprofile(self.secprofile).read()
        self.assertTrue(secprofile_info['uuid'] == self.secprofile['uuid'],
                        "secprofile uuid should be the same UUID as stored")

    def test_secprofile_delete(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_secprofile_query(self):
        query = self.nvp.securityprofile().query()
        query_results = query.uuid(self.secprofile['uuid']).results()
        self.assertTrue(query_results['result_count'] == 1,
                        "Query on UUID should return single result")

    def test_secprofile_update(self):
        current_name = self.secprofile['display_name']
        new_name = "test%s" % current_name
        secprofile_object = self.nvp.securityprofile(self.secprofile)
        changed_secprofile = secprofile_object.display_name(new_name).update()
        self.assertTrue(changed_secprofile['display_name'] == new_name and
                        self.secprofile['display_name'] == current_name and
                        changed_secprofile['uuid'] == self.secprofile['uuid'],
                        "Data on same UUID should be different post update")
