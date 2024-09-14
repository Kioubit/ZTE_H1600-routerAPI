#!/usr/bin/env python3
import configparser
from router import Router
import time
import datetime
import sys
import os


def print_stats(router_obj: Router, dsl_name: str, with_firmware_info=False):
    stats = router_obj.request_stats()
    dsl_stats = stats[0].to_dict('./OBJ_DSLINTERFACE_ID')["Instance"]
    uplink_stats_array = stats[1].to_dict("./ID_WAN_COMFIG")["Instance"]
    uplink_stats = None
    for item in uplink_stats_array:
        if item["WANCName"] == dsl_name:
            uplink_stats = item
            break
    print("Brief overview:")
    if with_firmware_info:
        firmware = router_obj.request_firmware_info().to_dict('./OBJ_DEVINFO_ID')["Instance"]
        print(f"{'Firmware:':>10} {firmware['SoftwareVer']} - {firmware['VerDate']}")
    print(f"{'DSL:':>10}")
    print(f"{'Status:':>25} {dsl_stats['Status']}")
    print(f"{'Uptime:':>25} {str(datetime.timedelta(seconds=int(dsl_stats['Showtime_start'])))}")
    print(
        f"{'Speed:':>25} {str(int(dsl_stats['Downstream_current_rate']) / 1000):>7}"
        f" / {str(int(dsl_stats['Upstream_current_rate']) / 1000):<7} (mbps)")
    print(
        f"{'Max Speed:':>25} {str(int(dsl_stats['Downstream_max_rate']) / 1000):>7}"
        f" / {str(int(dsl_stats['Upstream_max_rate']) / 1000):<7} (mbps)")
    print(f"{'Uplink:':>10}")
    print(f"{'Status (4/6):':>25} {uplink_stats['ConnStatus']}/{uplink_stats['ConnStatus6']}")
    print(
        f"{'Uptime (4/6):':>25} {str(datetime.timedelta(seconds=int(uplink_stats['UpTime'])))}"
        f" / {str(datetime.timedelta(seconds=int(uplink_stats['UpTimeV6'])))}")
    print(f"{'IPv4:':>25} {uplink_stats['IPAddress']}")
    print(f"{'IPv6:':>25} {uplink_stats['Gua1']}/{uplink_stats['Gua1PrefixLen']}")


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
        password = input("Enter router password:").strip()

    router_obj = Router(base_url, username, password)
    try:
        if sys.argv[1] == "overview":
            router_obj.login()
            print_stats(router_obj, dsl_name, with_firmware_info=True)
            router_obj.logout()
        elif sys.argv[1] == "restart":
            router_obj.login()
            router_obj.restart()
        elif sys.argv[1] == "raw":
            router_obj.login()
            stats = router_obj.request_stats()
            router_obj.logout()
            dsl_stats = stats[0].to_dict('./OBJ_DSLINTERFACE_ID')["Instance"]
            uplink_stats_array = stats[1].to_dict("./ID_WAN_COMFIG")["Instance"]
            uplink_stats = None
            for item in uplink_stats_array:
                if item["WANCName"] == dsl_name:
                    uplink_stats = item
                    break
            print(dsl_stats)
            print(uplink_stats)
        elif sys.argv[1] == "monitor":
            if len(sys.argv) != 3:
                print("Missing 'seconds' parameter")
                return
            router_obj.login()
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                print(
                    datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") + "\t(Refresh every " + sys.argv[2] + " sec)")
                print_stats(router_obj, dsl_name)
                time.sleep(int(sys.argv[2]))
        elif sys.argv[1] == "hosts":
            router_obj.login()
            hosts = router_obj.request_dhcp4_info().to_dict("OBJ_DHCPHOSTINFO_ID")["Instance"]
            print(f"{'Hostname':<25}  {'IP Address':<15}  {'Port':<5}  {'Mac Address':<17}  {'Expiry':<15}")
            print(f"{'':-<83}")
            for host in hosts:
                hostname = ""
                if host["OBJ_DHCPHOSTINFO_ID.HostName"] is not None:
                    hostname = host["OBJ_DHCPHOSTINFO_ID.HostName"]
                print(f"{hostname:<25.24}  {host['OBJ_DHCPHOSTINFO_ID.IPAddr']:<15.14}"
                      f"  {host['OBJ_DHCPHOSTINFO_ID.PhyPortName']:<5.4}  {host['OBJ_DHCPHOSTINFO_ID.MACAddr']:<17.16}"
                      f"  {host['OBJ_DHCPHOSTINFO_ID.ExpiredTime']:<15.14}")
            router_obj.logout()
        else:
            print_usage()
    except KeyboardInterrupt:
        print("Logging out")
        router_obj.logout()


def print_usage():
    print("CLI API for ZTE H1600 routers")
    print("Available commands: overview/raw/monitor <sec>/hosts/restart")


if __name__ == '__main__':
    main()