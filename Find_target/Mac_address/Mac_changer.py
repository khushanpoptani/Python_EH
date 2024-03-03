import re
import subprocess
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change mac address")
    parser.add_option("-m", "--mac", dest="new_mac_address", help="new mac address")

    (options, arguments) = parser.parse_args()

    if not options.interface:
        print(options.interface)
        parser.error("[-] Specify the interface or --help")

    elif not options.new_mac_address:
        parser.error("[-] Specify the new mac address or --help")

    return options

def change_mac(interface, new_mac_address):
    print('Changing Mac address of ', new_mac_address)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac_address])
    subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):
    interface_data = subprocess.check_output(["ifconfig", interface])

    old_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(interface_data))

    if old_mac:
        return old_mac.group(0)
    else:
        print("Could not find current mac addrerss")


options = get_arguments()
change_mac(options.interface, options.new_mac_address)
current_mac = get_current_mac(options.interface)

if current_mac == options.new_mac_address:
    print("Mac address was changed scuessfully :)")

else:
    print("We are unable to change the mac address try again :(")