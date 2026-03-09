import socket
import struct

# Create raw socket
sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

print("Sniffer Started...\n")

while True:
    raw_data, addr = sniffer.recvfrom(65536)

    # Ethernet header (first 14 bytes)
    eth_header = raw_data[:14]
    eth = struct.unpack("!6s6sH", eth_header)

    eth_protocol = socket.ntohs(eth[2])

    # Only process IPv4 packets
    if eth_protocol == 8:

        # IP header starts after Ethernet header
        ip_header = raw_data[14:34]

        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 15

        ttl = iph[5]
        protocol = iph[6]

        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])

        print("=================================")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dest_ip}")
        print(f"Protocol       : {protocol}")
        print(f"TTL            : {ttl}")
