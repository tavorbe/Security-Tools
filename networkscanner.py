# Import relevant modules
import scapy.all as scapy
import argparse

# This function allow the users to pass arguments (ip address or ip range) to the script with the execution.
# Execution example - python3 networkscanner.py -t 192.168.1.1/24
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Adresses')
    options = parser.parse_args()

    #Check for errors i.e if the user does not specify the target IP Address
    #Quit the program if the argument is missing
    #While quitting also display an error message
    if not options.target:
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")
    return options

# This function perform the network scanning
def scan(ip):
    # Create an ARP request frame using scapy
    arp_req_frame = scapy.ARP(pdst = ip)

    # Create an Ethernet frame (sending ARP request to who?)
    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")

    # Combine the ARP request and the Ethernet frame to a new frame (ip address/range + broadcast MAC address)
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    # The function that scapy provides to do the above tasks is called scapy.srp().
    # **This function takes the actual frame to be transmitted as an argument.
    # You can see that we have passed **broadcast_ether_arp_req_frame (our final combined frame) **is passed to the function below.
    # It also takes a **timeout **input which tells the scapy for how much time period it should wait to receive a response before moving further.
    # What this means is, from the below example **timeout = 1 means the scapy will wait for 1 second for the response and if the response is not received it will move further to send the packet to the next IP Address.
    # The argument verbose = False is not important and it only stops the scapy from printing its own messages on the screen.
    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip" : answered_list[i][1].psrc, "mac" : answered_list[i][1].hwsrc}
        result.append(client_dict)

    return result

def display_result(result):
    print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
    for i in result:
        print("{}\t{}".format(i["ip"], i["mac"]))
  


options = get_args()
scanned_output = scan(options.target)
display_result(scanned_output)

