#!/usr/bin/env python3
import configparser
from router import Router
import time
import datetime
import sys
import os
from getpass import getpass


def print_stats(stats: dict):
    firmware = stats["firmware"]
    dsl_stats = stats["dsl_stats"]
    uplink_stats = stats["uplink_stats"]
    map_e_status = stats["map_e_status"]

    print("Brief overview:")
    if firmware:
        print(f"{'Firmware:':>10} {firmware['SoftwareVer']} - {firmware['VerDate']}")
    print(f"{'DSL:':>10}")
    print(f"{'Status:':>25} {dsl_stats['Status']}")
    print(f"{'Uptime:':>25} {str(datetime.timedelta(seconds=int(dsl_stats['Showtime_start'])))}")
    print(
        f"{'Speed:':>25} {str(int(dsl_stats['Downstream_current_rate']) / 1000):>7}"
        f" / {str(int(dsl_stats['Upstream_current_rate']) / 1000):<7} (down/up mbps)")
    print(
        f"{'Max Speed:':>25} {str(int(dsl_stats['Downstream_max_rate']) / 1000):>7}"
        f" / {str(int(dsl_stats['Upstream_max_rate']) / 1000):<7} (down/up mbps)")
    print(f"{'Uplink:':>10}")
    print(f"{'Status (4/6):':>25} {uplink_stats['ConnStatus']}/{uplink_stats['ConnStatus6']}")
    print(
        f"{'Uptime (4/6):':>25} {str(datetime.timedelta(seconds=int(uplink_stats['UpTime'])))}"
        f" / {str(datetime.timedelta(seconds=int(uplink_stats['UpTimeV6'])))}")
    print(f"{'IPv4:':>25} {uplink_stats['IPAddress']}")
    print(f"{'IPv6:':>25} {uplink_stats['Gua1']}/{uplink_stats['Gua1PrefixLen']}")

    print()
    print(f"{'MAP-E Status:':>25} {"Connected" if map_e_status['ConnStatus'] == '1' else "Disconnected"}")
    print(f"{'MAP-E v4:':>25} {map_e_status['LocalIPv4Addr']}")
    print(f"{'MAP-E PSID:':>25} Length: {map_e_status["PSIDLen"]}, Offset: {map_e_status["PSIDOffset"]}, PortSetID: {map_e_status["PortSetID"]}")
    print(f"{'MAP-E Port ranges:':>25} {ellipsize_middle([part for part in (map_e_status.get('PortRange') or '').split(";") if part], 10)}")


def fetch_stats(router_obj: Router, dsl_name: str, with_firmware_info: bool) -> dict:
    stats = router_obj.request_stats()
    dsl_stats = stats[0].to_dict('./OBJ_DSLINTERFACE_ID')["Instance"]
    uplink_stats_array = stats[1].to_dict("./ID_WAN_COMFIG")["Instance"]
    uplink_stats = None
    for item in uplink_stats_array:
        if item["WANCName"] == dsl_name:
            uplink_stats = item
            break
    map_e_status = router_obj.request_map_e_info().to_dict("./OBJ_MAPESTATUS_ID")["Instance"]
    firmware = None
    if with_firmware_info:
        firmware = router_obj.request_firmware_info().to_dict('./OBJ_DEVINFO_ID')["Instance"]
    return {"map_e_status": map_e_status, "dsl_stats": dsl_stats,
              "uplink_stats": uplink_stats, "firmware": firmware}


def ellipsize_middle(text: str| list, max_length: int, placeholder="...") -> str:
    if len(text) <= max_length:
        return text
    keep = max_length - len(placeholder)
    left = (keep // 2)
    right = keep - left

    return f"{text[:left]}{placeholder}{text[-right:]}"

def main():
    base_url = "http://192.168.1.1/"
    username = "admin"
    password = None
    dsl_name = "VDSL_INTERNET"

    if len(sys.argv) < 2:
        print_usage()
        return

    parser = configparser.RawConfigParser()
    if os.path.isfile("config"):
        parser.read("config")
        base_url = parser.get("config", "base_url")
        dsl_name = parser.get("config", "dsl_name")
        username = parser.get("config", "username")
        password = parser.get("config", "password")

    if not password:
        password = getpass("Enter router password:").strip()

    router_obj = Router(base_url, username, password)
    try:
        if sys.argv[1] == "overview":
            router_obj.login()
            stats = fetch_stats(router_obj, dsl_name, with_firmware_info=True)
            print_stats(stats)
            router_obj.logout()
        elif sys.argv[1] == "restart":
            router_obj.login()
            router_obj.restart()
        elif sys.argv[1] == "raw":
            router_obj.login()
            result = fetch_stats(router_obj, dsl_name, with_firmware_info=True)
            import json
            print(json.dumps(result))
        elif sys.argv[1] == "monitor":
            if len(sys.argv) != 3:
                print("Missing 'seconds' parameter")
                return
            router_obj.login()
            while True:
                stats = fetch_stats(router_obj, dsl_name, with_firmware_info=False)
                os.system('cls' if os.name == 'nt' else 'clear')
                print(
                    datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") + "\t(Refresh every " + sys.argv[2] + " sec)")
                print_stats(stats)
                time.sleep(int(sys.argv[2]))
        elif sys.argv[1] == "dhcp":
            router_obj.login()
            hosts = router_obj.request_dhcp4_info().to_dict("OBJ_DHCPHOSTINFO_ID")["Instance"]
            print("DHCP allocations")
            print(f"{'Hostname':<25}  {'IP Address':<15}  {'Port':<5}  {'Mac Address':<17}  {'Expiry':<15}")
            print(f"{'':-<83}")
            for host in hosts:
                print(f"{host.get('OBJ_DHCPHOSTINFO_ID.HostName') or '':<25.24}"
                      f"  {host['OBJ_DHCPHOSTINFO_ID.IPAddr']:<15.14}"
                      f"  {host['OBJ_DHCPHOSTINFO_ID.PhyPortName']:<5.4}  {host['OBJ_DHCPHOSTINFO_ID.MACAddr']:<17.16}"
                      f"  {host['OBJ_DHCPHOSTINFO_ID.ExpiredTime']:<15.14}")
            router_obj.logout()
        elif sys.argv[1] == "hosts":
            router_obj.login()
            status_responses = router_obj.request_local_net_status()
            lan_devices = status_responses[0].to_dict("./OBJ_ACCESSDEV_ID")["Instance"]
            wlan_devices = status_responses[1].to_dict("./OBJ_ACCESSDEV_ID")["Instance"]

            def print_devices(devices):
                print(f"{'Hostname':<25}  {'IPv4 Address':<15}  {'IPv6 Address':<38}  {'Mac Address':<17}  {'Port':<6}")
                print(f"{'':-<110}")
                for device in devices:
                    print(f"{device.get('HostName') or '':<25.24}  {device.get('IPAddress') or '':<15.14}"
                          f"  {device.get('IPV6Address') or '':<38.37}"
                          f"  {device.get('MACAddress') or '':<17.16}  {device.get('AliasName') or '':<6.5}")

            print("LAN devices")
            print_devices(lan_devices)
            print("")

            print("WLAN devices")
            print_devices(wlan_devices)
            router_obj.logout()
        else:
            print_usage()
    except KeyboardInterrupt:
        print("Logging out")
        router_obj.logout()


def print_usage():
    print("CLI API for ZTE H1600 routers")
    print("Available commands: overview/raw/monitor <sec>/hosts/dhcp/restart")


if __name__ == '__main__':
    main()
