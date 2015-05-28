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


class TestLogicalSwitchPort(tests.base.IntegrationTestBase):

    def setUp(self):
        super(TestLogicalSwitchPort, self).setUp()
        self.switch = self.nvp.lswitch().create()
        self.switchport = self.nvp.lswitch_port(self.switch).create()

    def tearDown(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.nvp.lswitch_port(self.switchport).delete()
        self.nvp.lswitch(self.switch).delete()

    def test_switchport_create(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_switchport_delete(self):
        """Functionality is implicit in setUp and tearDown. If this passes
        those must have passed"""
        self.assertTrue(True)

    def test_switchport_update(self):
        current_name = self.switchport['display_name']
        new_name = "test%s" % current_name
        port_object = self.nvp.lswitch_port(self.switch, self.switchport)
        changed_port = port_object.display_name(new_name).update()
        self.assertTrue(changed_port['display_name'] == new_name and
                        self.switchport['display_name'] == current_name and
                        changed_port['uuid'] == self.switchport['uuid'],
                        "Data on same UUID should be different post update")

    def test_switchport_read(self):
        port_object = self.nvp.lswitch_port(self.switch, self.switchport)
        port_status = port_object.read()
        self.assertTrue(port_status['type'] == 'LogicalSwitchPortConfig',
                        "Port info should be the correct type of JSON")

    def test_switchport_status(self):
        port_object = self.nvp.lswitch_port(self.switch, self.switchport)
        port_status = port_object.status()
        self.assertTrue(port_status['type'] == 'LogicalSwitchPortStatus',
                        "Port status should be the correct type of JSON")

    def test_switchport_statistics(self):
        port_object = self.nvp.lswitch_port(self.switch, self.switchport)
        port_status = port_object.statistics()
        self.assertTrue(type(port_status) is dict and
                        'rx_bytes' in port_status,
                        "Port status should be the correct type of JSON")
