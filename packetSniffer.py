import socket
import struct
import textwrap
import argparse
import signal
import sys
from typing import Protocol, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class ProtocolType(Enum):
    ICMP = 1
    TCP = 6
    UDP = 17
    IPV4 = 8

@dataclass
class EthernetFrame:
    dest_mac: str
    source_mac: str
    protocol: int
    data: bytes

@dataclass
class IPv4Packet:
    version: int
    header_length: int
    ttl: int
    protocol: int
    source: str
    target: str
    data: bytes

@dataclass
class ICMPPacket:
    type: int
    code: int
    checksum: int
    data: bytes

@dataclass
class TCPSegment:
    src_port: int
    dest_port: int
    sequence: int
    acknowledgment: int
    flags: dict
    data: bytes

@dataclass
class UDPSegment:
    src_port: int
    dest_port: int
    length: int
    data: bytes

class PacketSniffer:
    """A class to handle packet sniffing operations."""
    
    def __init__(self, interface: str = None, filter_protocol: Optional[ProtocolType] = None):
        """
        Initialize the packet sniffer.
        
        Args:
            interface: Network interface to sniff on
            filter_protocol: Protocol to filter packets by
        """
        self.interface = interface
        self.filter_protocol = filter_protocol
        self.running = True
        self.conn = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print("\nShutting down packet sniffer...")
        self.running = False
        if self.conn:
            self.conn.close()
        sys.exit(0)

    def start(self):
        """Start the packet sniffer."""
        try:
            self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if self.interface:
                self.conn.bind((self.interface, 0))
            
            print(f"Starting packet sniffer on {self.interface or 'default interface'}")
            print("Press Ctrl+C to stop")
            
            while self.running:
                try:
                    raw_data, addr = self.conn.recvfrom(65536)
                    self.process_packet(raw_data)
                except socket.error as e:
                    print(f"Error receiving packet: {e}")
                    continue
                    
        except PermissionError:
            print("Error: This program requires root/administrator privileges")
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {e}")
            sys.exit(1)

    def process_packet(self, raw_data: bytes):
        """Process a single packet."""
        try:
            eth_frame = self.ethernet_frame(raw_data)
            print("\nEthernet Frame:")
            print(f"\tDestination: {eth_frame.dest_mac}, Source: {eth_frame.source_mac}, Protocol: {eth_frame.protocol}")

            if eth_frame.protocol == ProtocolType.IPV4.value:
                ip_packet = self.ipv4_packet(eth_frame.data)
                print("\tIPv4 Packet:")
                print(f"\t\tVersion: {ip_packet.version}, Header Length: {ip_packet.header_length}, TTL: {ip_packet.ttl}")
                print(f"\t\tProtocol: {ip_packet.protocol}, Source: {ip_packet.source}, Target: {ip_packet.target}")

                if self.filter_protocol and ip_packet.protocol != self.filter_protocol.value:
                    return

                if ip_packet.protocol == ProtocolType.ICMP.value:
                    self.process_icmp(ip_packet.data)
                elif ip_packet.protocol == ProtocolType.TCP.value:
                    self.process_tcp(ip_packet.data)
                elif ip_packet.protocol == ProtocolType.UDP.value:
                    self.process_udp(ip_packet.data)
                else:
                    print("\tData:")
                    print(self.format_multiline_data("\t\t", ip_packet.data))
            else:
                print("Data:")
                print(self.format_multiline_data("\t", eth_frame.data))

        except Exception as e:
            print(f"Error processing packet: {e}")

    def ethernet_frame(self, data: bytes) -> EthernetFrame:
        """Unpack ethernet frame."""
        dest_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return EthernetFrame(
            dest_mac=self.get_mac_addr(dest_mac),
            source_mac=self.get_mac_addr(source_mac),
            protocol=socket.htons(proto),
            data=data[14:]
        )

    def ipv4_packet(self, data: bytes) -> IPv4Packet:
        """Unpack IPv4 packet."""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return IPv4Packet(
            version=version,
            header_length=header_length,
            ttl=ttl,
            protocol=proto,
            source=self.ipv4(src),
            target=self.ipv4(target),
            data=data[header_length:]
        )

    def process_icmp(self, data: bytes):
        """Process ICMP packet."""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        print("\tICMP Packet:")
        print(f"\t\tType: {icmp_type}, Code: {code}, Checksum: {checksum}")
        print("\t\tData")
        print(self.format_multiline_data("\t\t\t", data[4:]))

    def process_tcp(self, data: bytes):
        """Process TCP segment."""
        tcp = self.tcp_segment(data)
        print("\tTCP Segment:")
        print(f"\t\tSource Port: {tcp.src_port}, Destination Port: {tcp.dest_port}")
        print(f"\t\tSequence: {tcp.sequence}, Acknowledgement: {tcp.acknowledgment}")
        print("\t\tFlags:")
        for flag, value in tcp.flags.items():
            print(f"\t\t\t{flag}: {value}")
        print("\t\tData:")
        print(self.format_multiline_data("\t\t\t", tcp.data))

    def process_udp(self, data: bytes):
        """Process UDP segment."""
        udp = self.udp_segment(data)
        print("\tUDP Segment")
        print(f"\t\tSource Port: {udp.src_port}, Destination Port: {udp.dest_port}, Length: {udp.length}")
        print("\t\tData:")
        print(self.format_multiline_data("\t\t\t", udp.data))

    @staticmethod
    def get_mac_addr(bytes_addr: bytes) -> str:
        """Return properly formatted MAC address."""
        bytes_str = map('{02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    @staticmethod
    def ipv4(addr: bytes) -> str:
        """Return properly formatted IPv4 address."""
        return '.'.join(map(str, addr))

    @staticmethod
    def tcp_segment(data: bytes) -> TCPSegment:
        """Unpack TCP segment."""
        (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = {
            'URG': (offset_reserved_flags & 32) >> 5,
            'ACK': (offset_reserved_flags & 16) >> 4,
            'PSH': (offset_reserved_flags & 8) >> 3,
            'RST': (offset_reserved_flags & 4) >> 2,
            'SYN': (offset_reserved_flags & 2) >> 1,
            'FIN': offset_reserved_flags & 1
        }
        return TCPSegment(
            src_port=src_port,
            dest_port=dest_port,
            sequence=sequence,
            acknowledgment=acknowledgment,
            flags=flags,
            data=data[offset:]
        )

    @staticmethod
    def udp_segment(data: bytes) -> UDPSegment:
        """Unpack UDP segment."""
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return UDPSegment(
            src_port=src_port,
            dest_port=dest_port,
            length=size,
            data=data[8:]  # Fixed: Now correctly returns the UDP payload
        )

    @staticmethod
    def format_multiline_data(prefix: str, string: bytes, size: int = 80) -> str:
        """Format data for multi-line output."""
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    parser = argparse.ArgumentParser(description='Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff on')
    parser.add_argument('-f', '--filter', type=int, help='Protocol number to filter (1=ICMP, 6=TCP, 17=UDP)')
    args = parser.parse_args()

    filter_protocol = None
    if args.filter:
        try:
            filter_protocol = ProtocolType(args.filter)
        except ValueError:
            print(f"Invalid protocol number: {args.filter}")
            sys.exit(1)

    sniffer = PacketSniffer(args.interface, filter_protocol)
    sniffer.start()

if __name__ == '__main__':
    main()

