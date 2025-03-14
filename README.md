# ZTE_H1600-routerAPI
CLI API for ZTE H1600 routers

Tested with firmware v7.x.x
## Usage
```
# python main.py
Available commands: overview/raw/monitor <sec>/hosts/dhcp/restart
# python main.py overview
Brief overview:
 Firmware: VXXXXXXX - XXXXXXXXXXX
      DSL:
                  Status: Up
                  Uptime: 0:15:10
                   Speed:  20.021 / 10.149   (mbps)
               Max Speed: 200.193 / 100.536  (mbps)
   Uplink:
            Status (4/6): Connected/Connected
            Uptime (4/6): 0:14:42 / 0:14:49
                    IPv4: XXX.XXX.XXX.XXX
                    IPv6: XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX/64
            MAP-E Status: Connected
                MAP-E v4: XXX.XXX.XXX.XXX
              MAP-E PSID: Length: 6, Offset: 6, PortSetID: 12
       MAP-E Port ranges: ...

```
