import re
import scapy.all as scapy
import optparse


def get_ip():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip", dest="target_ip", help="Enter the target ip or ip range eg -: 10.0.0.1/24 or 10.0.0.4")
    (options, agruments) = parser.parse_args()

    if not options.target_ip:
        print("Enter the target ip or ip range -help for more information")

    return options.target_ip


def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    mac_broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") #Sends destination mac to broadcast mac
    arp_request_mac_broadcast = mac_broadcast/arp_request
    answered_list = scapy.srp(arp_request_mac_broadcast, timeout=1, verbose=False)[0] #send request packet(srp) can use modify ether

    #arp_request_mac_broadcast.show() (Shows all the details of this variable or the request sent
    #scapy.ls(scapy.Ether()) (List all the fields we can set in the above scapy.Ether(....))
    #scapy.ls(scapy.ARP()) (List all the fields we can set in the above scapy.ARP(....))
    #arp_request.pdst = ip  (alternate step to set the find ip address in arp_request)

    complete_data = []  # helps to store the data in easy format
    for element in answered_list:
        # print(elements[1].show)
        # elements[1].show shows the inside fields and we can use that to print that specific part
        data_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        complete_data.append(data_dict)

    return complete_data



def print_data(ip_mac_list):
    print("")
    print("IP ADDRESS\t\t\t MAC ADDRESS \n---------------------------------------------------")

    for data in ip_mac_list:
        print(data["IP"]+ "\t\t\t"+ data["MAC"])


    print("")
    #print(complete_data)



print_data(scan(get_ip()))



#192.168.57.241