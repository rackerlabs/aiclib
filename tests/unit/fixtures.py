import json

LSWITCH_Q = json.dumps(json.loads("""
{
  "results": [
    {
      "display_name": "lswitch1",
      "_href": "/ws.v1/lswitch/0fb9adc9-3b7e-41da-bd2a-43da65311111",
      "tags": [
        {
          "scope": "os_tid",
          "tag": "12345"
        },
        {
          "scope": "neutron_net_id",
          "tag": "0edf4a88-975b-4b19-aeda-ff657494df1c"
        }
      ],
      "transport_zones": [
        {
          "zone_uuid": "3e2b4fcd-6875-44fe-acae-e640b625a216",
          "binding_config": {
            "vxlan_transport": [
              {
                "transport": 11111
              }
            ],
            "vlan_translation": []
          },
          "transport_type": "vxlan"
        },
        {
          "zone_uuid": "3e2b4fcd-6875-44fe-acae-e640b625a216",
          "transport_type": "stt"
        }
      ],
      "_schema": "/ws.v1/schema/LogicalSwitchConfig",
      "port_isolation_enabled": false,
      "replication_mode": "service",
      "type": "LogicalSwitchConfig",
      "uuid": "0fb9adc9-3b7e-41da-bd2a-43da65311111"
    },
    {
      "display_name": "lswitch2",
      "_href": "/ws.v1/lswitch/0fb9adc9-3b7e-41da-bd2a-43da65322222",
      "tags": [
        {
          "scope": "os_tid",
          "tag": "12345"
        },
        {
          "scope": "neutron_net_id",
          "tag": "0edf4a88-975b-4b19-aeda-ff657494df1c"
        }
      ],
      "transport_zones": [
        {
          "zone_uuid": "3e2b4fcd-6875-44fe-acae-e640b625a216",
          "binding_config": {
            "vxlan_transport": [
              {
                "transport": 22222
              }
            ],
            "vlan_translation": []
          },
          "transport_type": "vxlan"
        },
        {
          "zone_uuid": "3e2b4fcd-6875-44fe-acae-e640b625a216",
          "transport_type": "stt"
        }
      ],
      "_schema": "/ws.v1/schema/LogicalSwitchConfig",
      "port_isolation_enabled": false,
      "replication_mode": "service",
      "type": "LogicalSwitchConfig",
      "uuid": "0fb9adc9-3b7e-41da-bd2a-43da65322222"
    }
  ],
  "result_count": 2
}
"""))
