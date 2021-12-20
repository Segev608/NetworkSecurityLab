from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.plist import PacketList
import matplotlib.pyplot as plt
from collections import Counter
import numpy as np
import argparse

# based on the frequency (count) of IP addresses with SYN-ONLY:
ANALYSIS_MODES = {
    'extreme': "detects *all* addresses which potentially could be SYN-flood attackers",
    'strict': "detects only above *average* addresses which potentially could be SYN-flood attackers",
    'normal': "detects only *highest 10%* addresses which potentially could be SYN-flood attackers"
}

# by default - strict
CHOSEN_MODE = list(ANALYSIS_MODES.keys())[1]

# ignore option, see definition in parse_args function
# by default, it's filter SYN-ONLY count with 5

# the reason is because there maybe legitimate SYN which
# does not received any SYN-ACK and send again
# (so 5 is the upper threshold)
IGNORE_COUNT = 5

# change visualise to True for additional
# information gathered alongside the analysis
VERBOSE = False

# contains frequency of every SYN-ONLY per IPv4 address sniffed
frequency = None


def detect_suspicious(pcap: PacketList, verbose: bool = False):
    """
    filters the ips which suspected to be problematic
    based on the indicators which described in here
    :param pcap: packet capture list to analyze
    :param verbose: print findings
    :return: suspicious IPv4 addresses
    """
    initiators = set()
    closers = set()
    acknowledged = set()

    # my strategy is to find all of the IP addresses
    # which initiate conversation, gets an SYN+ACK and
    # never returns an ACK for answer but leaving the server
    # side waiting...

    # inside TCP header, SYN is the second flag
    # which makes it's value 2 (after FIN with 1)
    SYN = 0x2
    ACK = 0x10

    for pkt in pcap:
        if pkt.haslayer(TCP):
            # extract IP source address from packet
            flags = pkt[TCP].flags.value
            ip_src = pkt[IP].src

            # find initiators
            if flags == SYN:
                initiators.add(ip_src)

            # find responsive initiators (did send ACK back)
            # we don't care if those are ACK inside any middle
            # conversation, we just want to filter those out
            if flags == ACK:
                closers.add(ip_src)

            # find SYN+ACK responses
            if flags == SYN + ACK:
                acknowledged.add(ip_src)

    suspicious = initiators - acknowledged.union(closers)
    return suspicious


def frequency_analysis(all_ips: list, suspicious: set):
    global frequency
    freq = Counter(all_ips)

    for ip in list(freq.keys()):
        # filter innocent ip addresses
        if ip not in suspicious:
            freq.pop(ip)

    frequency = freq

    # this visualization gives us intuition about
    # the behaviour of the attacker based on the normal
    # users (this quite important because there could be times
    # where founding out there is suspicious user which initiate conversation
    # thousands of time but it's normally fine based on the scenario)

    # I'm filtering low values attackers :)
    if CHOSEN_MODE == 'extreme':
        return sorted(freq, key=freq.get, reverse=True)

    # filter "noise" - lower values
    if IGNORE_COUNT:
        data = [freq[ip] for ip in freq if freq[ip] > IGNORE_COUNT]
    else:
        data = [freq[ip] for ip in freq]

    # find percentile based on mode of operation (see explanation above)
    percent = np.percentile(data, 50 if CHOSEN_MODE == 'strict' else 90)
    if VERBOSE:
        x = np.arange(0, len(data))
        plt.title('Frequency analysis on suspicious IPv4 addresses')
        plt.ylabel('frequency per IP address')
        plt.text(0, percent + 0.25, f'percentile={percent}')
        plt.plot(x, [percent] * len(data), color='red')
        plt.bar(x, height=sorted(data))
        plt.show()

    # after seeing this graph we can better understand the situation and
    # maybe respond differently on other situations
    return sorted(freq, key=freq.get, reverse=True)[:sum(f > percent for f in data)]


def entry():
    global IGNORE_COUNT, VERBOSE, CHOSEN_MODE
    print('[SYSTEM]> #### SYN-flood attack indicator ####')
    print('[SYSTEM]> Please choose mode of operation')
    print('[SYSTEM]> options are - [strict|normal|extreme|help], (default is strict)')

    # handle 'mode' argument
    mode = None
    while mode not in list(ANALYSIS_MODES.keys()):
        mode = input('[User]>')
        if mode in ['h', 'help']:
            for m, h in ANALYSIS_MODES.items():
                print(f'\tmode={m}, explanation={h}')
        elif mode in list(ANALYSIS_MODES.keys()):
            break
        elif mode == '':
            # use default value
            mode = CHOSEN_MODE
        else:
            print('[ERROR]> Invalid mode! see options above')
    CHOSEN_MODE = mode

    # handle 'ignore' argument
    if CHOSEN_MODE != 'extreme':
        # extreme mode returns everything so no filter required here
        print(f'[SYSTEM]> chosen mode={CHOSEN_MODE}')
        print('[SYSTEM]> specify ignore value [filters addresses with less than [i] SYN-ONLY packets]')
        c = input('[SYSTEM]> specify number for value or press [-] for no-ignore:')
        IGNORE_COUNT = int(c) if c.isdecimal() else None

    # handle 'verbose' argument
    v = input('[SYSTEM]> Visualise & Verbose process? [Y/n] - ').lower()
    VERBOSE = v == 'y'


def store_attackers(malicious_ips: list):
    with open('SYN_flood_attackers.txt', 'w') as file:
        if VERBOSE:
            print('[SYSTEM]> Analysis found [sorted by severity]:')
            print('\n')
        for i, ip in enumerate(malicious_ips):
            line = f'[{i}] {ip}, #SYN-ONLY = {frequency[ip]}'
            file.write(line + '\n')
            if VERBOSE:
                print(line)


if __name__ == '__main__':
    try:
        entry()
        capture = rdpcap("SynFloodSample.pcap")
        entire_ips = [pkt[IP].src for pkt in capture if pkt.haslayer(TCP)]
        ips = detect_suspicious(capture, verbose=VERBOSE)
        attackers = frequency_analysis(list(entire_ips), ips)
        store_attackers(attackers)
    except KeyboardInterrupt:
        print('exiting...')
        exit(0)
