#this is a basic tool that reads a Wireshark packet capture (PCAP) file and organizes the network data using linked lists and hash tables. 
# The tool counts the number of packets per IP address and identifies the most common protocols, as well as the smallest and largest packet size

import pyshark

protocol_counts = {}
ip_counts = {}

class PacketNode:
    def __init__(self, src_ip, dest_ip, protocol, size):
        self.src_ip = src_ip # source IP address of the packet.
        self.dest_ip = dest_ip # destination IP address of the packet.
        self.protocol = protocol # protocol type (e.g., TCP, UDP) for the packet.
        self.size = size # size of the packet in bytes.
        self.next = None

# Linked list to store packets
class PacketLinkedList:
    def __init__(self):
        self.head = None

    def add_packet(self, src_ip, dest_ip, protocol, size): #create new instance of the PacketNode class, which represents a single node in the linked list.    
        new_node = PacketNode(src_ip, dest_ip, protocol, size) #node stores the packet’s details (src_ip, dest_ip, protocol, size) and has a reference to the next node
        if not self.head: #If linkedlist is empty, new node becomes the head
            self.head = new_node 
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = new_node #new node is added to end of list by setting last node's next reference to newly created node

    def find_largest_and_smallest_packet_size(self):
        if not self.head:
            return None, None  # If the list is empty
        
        # Initialize largest and smallest packet size
        largest_size = self.head.size
        smallest_size = self.head.size

        # Traverse linked list to find the largest and smallest packet sizes
        current = self.head
        while current:
            if current.size > largest_size:
                largest_size = current.size
            if current.size < smallest_size:
                smallest_size = current.size
            current = current.next

        return largest_size, smallest_size

# Initialize the linked list
packet_list = PacketLinkedList()

# Update protocol count
def update_protocol_count(protocol):
    if protocol in protocol_counts:
        protocol_counts[protocol] += 1
    else:
        protocol_counts[protocol] = 1

# Update IP address count
def update_ip_count(ip):
    if ip in ip_counts:
        ip_counts[ip] += 1
    else:
        ip_counts[ip] = 1

def process_packet(packet):
    try:
        # Extract source and destination IP addresses
        src_ip = packet.ip.src
        dest_ip = packet.ip.dst

        # Default protocol = Unknown
        protocol = "Unknown"

        # Check for application layer protocols
        if hasattr(packet, 'highest_layer'):
            protocol = packet.highest_layer

            if protocol == "TCP": # make sure the packets labeled TCP are not FTP by checking for FTP in packet info
                # FTP operates over TCP, which is the transport protocol used by FTP. 
                # When analyzing packets, they may be identified as TCP packets that are used for FTP communication.
                if hasattr(packet, 'ftp'):
                    protocol = "FTP"  # Override to FTP

        # Print the packet layers and extracted protocol
        print(f"Extracted Protocol: {protocol}, Layers: {[layer.layer_name for layer in packet.layers]}")

        # Extract packet size
        size = int(packet.length)

        # Add packet details to linkedlist
        packet_list.add_packet(src_ip, dest_ip, protocol, size)

        # Update protocol and IP counts
        update_protocol_count(protocol)
        update_ip_count(src_ip)
        update_ip_count(dest_ip)

    except AttributeError as e: #error handling
        print(f"Failed to process packet: {e}")
        pass

# Parse the PCAP file
def parse_pcap(file_path):
    capture = pyshark.FileCapture(file_path)
    for packet in capture:
        process_packet(packet)

# Display results
def display_results():
    print("\nProtocol Counts:")
    if protocol_counts:
        for protocol, count in protocol_counts.items():
            print(f"{protocol}: {count}")
    else:
        print("No protocols found.")
    
    print("\nIP Address Counts:")
    if ip_counts:
        for ip, count in ip_counts.items():
            print(f"{ip}: {count}")
    else:
        print("No IP addresses found.")

    # After processing packets and adding them to the linked list
    largest, smallest = packet_list.find_largest_and_smallest_packet_size()

    print(f"Largest Packet Size: {largest} bytes")
    print(f"Smallest Packet Size: {smallest} bytes")


# Path to the PCAP file you uploaded
pcap_file_path = '/Users/sarahzhou/Downloads/set1.pcap'

# Parse the PCAP file and display results
parse_pcap(pcap_file_path)
display_results()