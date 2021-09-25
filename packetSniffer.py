import socket
import struct
import textwrap
from typing import Protocol

#these TABS are for making the output more readable
TAB_1 = '\t'
TAB_2 = '\t\t'
TAB_3 = '\t\t\t'
TAB_4 = '\t\t\t\t'

DATA_TAB_1 = '\t'
DATA_TAB_2 = '\t\t'
DATA_TAB_3 = '\t\t\t'
DATA_TAB_4 = '\t\t\t\t'

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)

        dest_mac, source_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\n Ethernet Frame:") 
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol:{}'.format(dest_mac, source_mac, eth_proto))

        # 8 is for ipv4
        if eth_proto == 8:
           (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
           print(TAB_1 + 'IPV4 Packet:')
           print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
           print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

           # ICMP
           if proto == 1:
               (icmp_type, code, checksum, data) = icmp_packet(data)
               print(TAB_1 + 'ICMP Packet:')
               print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
               print(TAB_2 + 'Data')
               print(format_multiline_data(DATA_TAB_3, data))   


            # TCP
           elif proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port:{}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement:{}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {},PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multiline_data(DATA_TAB_3, data))

            # UDP
           elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment')
                print(TAB_2 + 'Source Port: {},, Destination Port: {}, Length: {}.'.format(src_port, dest_port, length))

            # others
           else:
                print(TAB_1 +'Data:')
                print(format_multiline_data(DATA_TAB_2, data))

        else:
            print('Data:')
            print(format_multiline_data(DATA_TAB_1, data))

        




#unpacks ethernet frame
def ethernet_frame(data):
    #grabs the 1st 14bytes and unpack it which gives destination, source & type
    dest_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14]) 
    return get_mac_addr(dest_mac), get_mac_addr(source_mac), socket.htons(proto), data[14:]

#returns properly formatted mac address [AA:BB:CC:DD:EE:FF]
def get_mac_addr(bytes_addr):
    bytes_str = map('{02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#unpackes IPv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#return properly formatted ipv4 address [xxx.xxx.xxx.xxx] 
def ipv4(addr):
    return '.'.join(map(str, addr))

#unpacks ICMP packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#unpack the TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[:8]

#returns properly formatted multi-line data
def format_multiline_data(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

