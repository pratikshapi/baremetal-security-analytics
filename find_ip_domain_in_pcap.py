'''
Write a code for resolution of IP address to check for the domain name in the ubuntu-feb-13.pcap file.
'''

from scapy.all import *

file_name = "macos-mar-21"
# ip_address = ["212.70.149.38", "91.210.107.28", "91.189.91.38", "255.255.255.255", "224.0.0.251", "200.123.26.188"]
# ofile = open(file_name + '-resolved.txt', 'w')

ip = "17.253.144.10"

def domain_resolution():
    # packets = rdpcap('ubuntu-feb-13.pcap')
    with PcapReader(file_name + '.pcap') as pcap_reader:
        for packet in pcap_reader:
            if packet.haslayer(DNS):
                dns_packets = packet[DNS]
                for dns_packet in dns_packets:
                    if dns_packet[DNS].an is not None and "rdata" in dns_packet[DNS].an.fieldtype.keys():
                        if str(dns_packet[DNS].an.rdata) == ip:
                            print(dns_packet[DNS].show())

    exit()




domain_resolution()

'''



                # for dns_packet in dns_packets:
                #     if dns_packet[DNS].an and dns_packet[DNS].an.rdata and dns_packet[DNS].an.rdata == ip_address:
                #         print(dns_packet[DNS].show())
                #         print(dns_packet[DNSQR].qname.decode())

    for ip in ip_address:
        
        
        dns_packets_with_ip = dns_packets.filter(lambda p: p[DNS].an and p[DNS].an.rdata == ip)
        print(dns_packets_with_ip)
        for packet in dns_packets_with_ip:
            print(packet[DNSQR].qname.decode()) 


# Set the IP address you want to look for
ip_address = ["88.214.26.53", "212.70.149.38", "170.39.218.4", "91.210.107.28", "134.209.37.160", "134.122.51.63", "176.111.174.85", "179.60.147.156", "162.142.125.248", "239.255.255.250", "176.111.174.95", "255.255.255.255", "0.0.0.0", "23.45.233.35", "224.0.0.251", "17.253.144.10", "224.0.0.252", "192.229.211.108"]

# Load the PCAP file
pcap_file = "ubuntu-feb-13.pcap"
packets = rdpcap(pcap_file)

# Extract DNS queries and responses
dns_packets = packets.filter(lambda p: p.haslayer(DNS))

# Filter for the given IP address
for ip in ip_address:
    dns_packets = dns_packets.filter(lambda p: p[DNS].an and p[DNS].an.rdata == ip_address)

    # Print out the domain names
    for packet in dns_packets:
        print(packet[DNSQR].qname.decode())




'''
