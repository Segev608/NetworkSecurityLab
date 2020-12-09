from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import hashlib
import argparse
from scapy.layers.inet import IP, TCP

history = dict()
threshold = 10
iface = 'eth0'
source_ip = get_if_addr(iface)
source_mac = get_if_hwaddr(iface)

protective_mode = False


# using ARP request -> find IP
def find_mac(ip_address):
    pt = ARP(hwsrc=source_mac, psrc=source_ip, pdst=ip_address, hwdst=ETHER_BROADCAST)
    # send(pt, verbose=False)
    #  = sniff(filter='arp', count=1)
    ans, _ = sr(pt, timeout=0.6, verbose=False)
    # returns a set of all the mac address which their ARP response was sent directly to me
    return {pkt[ARP].hwsrc for pkt in list(zip(*ans))[1] if (pkt[ARP].op == 2)}  # and pkt[ARP].psrc == address)}


# using this trick, we can find the mac of some ip by using TCP-handshake
def handshake_validation(mac, ip):
    sport = random.randint(1024, 65535)

    ip = IP(src=source_ip, dst=ip)
    syn = TCP(sport=sport, dport=443, flags='S', seq=1000)
    syn_ack = srp1(ip / syn, timeout=0.5, verbose=False)
    if syn_ack:
        validated_mac = syn_ack[0].src
        if mac == validated_mac:
            return False
        else:
            return True
    return True


def arp_monitor(packet):
    if packet[ARP].op == 2:  # is-at
        mac, ip = packet[ARP].hwsrc, packet[ARP].psrc
        indicators = ['F']*3
        packet.sprintf("%ARP.hwsrc% %ARP.psrc% | time: "+str(time.time()))
        out = '[ '

        if timer_check(mac, ip):
            indicators[0] = 'T'
            out += 'timer '
        if who_has_check(mac, ip):
            indicators[1] = 'T'
            out += 'arpRequest '
        if handshake_validation(mac, ip):
            indicators[2] = 'T'
            out += 'tcpHandshake '
        if indicators.count('T') < 2:
            return False

        if protective_mode:
            try:
                subprocess.check_call(['arp', '-d', ip], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError:
                pass

        out += '] claims that you are under attack!'
        print(out, end='\r')
        return True


# level 1 indicator -> checks the delta-time between two 'is-at' ARP packets
def timer_check(mac, ip):
    current_time = time.time()
    key_packet = hashlib.md5(f"{mac}{ip}".encode()).digest()
    if key_packet in history:  # same packet has sent before
        delta_time = current_time - history[key_packet]
        if delta_time < threshold:
            history[key_packet] = current_time
            return True
    history[key_packet] = current_time  # store current packet time
    return False


def who_has_check(mac, ip):
    real_mac = find_mac(ip)
    response_mac = mac

    num_responses = len(real_mac)
    # print(real_mac, end='\n')
    # if the ARP-request has returned (1)more/(2)less then 1
    # it means that the attacker:
    # (1) the attacker and the legitimate PC are responding
    # (2) no legitimate PC and the attacker does not respond to ARP-request at all
    if num_responses != 1:
        return True
    real_mac = real_mac.pop()

    # if, inside the ARP-response, we got mac address which is different from the
    # first response -> it means that the legitimate PC has
    if real_mac != response_mac:
        return True
    return False


def parse_flags():
    global threshold, protective_mode
    parser = argparse.ArgumentParser()
    # insert the args variables to CLI for help
    parser.add_argument("-t", "--threshold", type=int, help="maximum threshold time between two 'is-at' ARP response")
    parser.add_argument("-p", "--protective", action='store_true', help="initiate protective mode - remove bad entries")
    args = parser.parse_args()
    if args.threshold:
        threshold = args.threshold

    protective_mode = args.protective


if __name__ == '__main__':
    try:
        parse_flags()
        while True:
            pkt = sniff(filter="arp", count=1, timeout=threshold)
            if not pkt or not arp_monitor(pkt[0]):
                print(' '*70, end='\r')
    except KeyboardInterrupt:
        print("Arpspoof detection tool is closing...")

