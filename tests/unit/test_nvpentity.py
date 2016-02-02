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

import mock

import aiclib.nvpentity
import tests.base as test_base


class LSwitchTestCase(test_base.UnitTestBase):
    def setUp(self):
        self.lswitch = aiclib.nvpentity.LSwitch(connection=mock.Mock(),
                                                uuid='asdf')

    def test_transport_zone(self):
        self.assertIsNone(self.lswitch.get("transport_zones"))

        cases = (
            (
                ('zone-uuid', 'vxlan'),
                {'vlan_id': 1337, 'vxlan_id': 31337},
                [{
                    'zone_uuid': 'zone-uuid',
                    'binding_config': {
                        "vlan_translation": [{'transport': 1337}],
                        "vxlan_transport": [{'transport': 31337}]},
                    'transport_type': 'vxlan'
                }]
            ),
            (
                ('zone-uuid', 'gre'),
                {'vlan_id': 1337},
                [{
                    'zone_uuid': 'zone-uuid',
                    'binding_config': {
                        "vlan_translation": [{'transport': 1337}]},
                    'transport_type': 'gre'
                }]
            ),
        )

        for case in cases:
            self.lswitch['transport_zones'] = None
            self.lswitch.transport_zone(*case[0], **case[1])
            self.assertEqual(case[2], self.lswitch['transport_zones'])
