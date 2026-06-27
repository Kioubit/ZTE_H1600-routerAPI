# ZTE_H1600-routerAPI
CLI API for ZTE H1600 routers

Tested with firmware v7.x.x
## Usage
```
# python main.py
Available commands: overview/raw/monitor <sec>/hosts/dhcp/restart
# python main.py overview
Brief overview:
 Firmware: VXXXXXXX - XXXXXXXXXXX  | Local time: XXXX-XX-XXT10:30:01
Brief overview:
      DSL:
                  Status: Disabled
                  Uptime: 0:00:00
                   Speed:     0.0 / 0.0     (down/up mbps)
               Max Speed:     0.0 / 0.0     (down/up mbps)
 Ethernet:
                  Status: Up
         Packets (rx/tx): 701162/316412
           Bytes (rx/tx): 715576291/85543150

Uplink DSL:
            Status (4/6): Unconfigured/Disconnected
            Uptime (4/6): 0:00:00 / 0:00:00
                    IPv4: 0.0.0.0
                    IPv6: ::/0

Uplink Ethernet:
            Status (4/6): Connected/Connected
            Uptime (4/6): 1:03:37 / 1:03:37
                    IPv4: XXX.XXX.XXX.XXX
                    IPv6: XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX/64

    MAP-E:
                  Status: Connected
                      v4: XXX.XXX.XXX.XXX
                    PSID: Length: 6, Offset: 1, PortSetID: 12
             Port ranges: ...
```
