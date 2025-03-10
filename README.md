# Packet Sniffer

A Python-based network packet sniffer that captures and analyzes network traffic. This tool provides detailed information about Ethernet frames, IPv4 packets, and their payloads (TCP, UDP, and ICMP).

## Features

- Captures and analyzes network packets in real-time
- Supports multiple protocols:
  - Ethernet frames
  - IPv4 packets
  - TCP segments
  - UDP segments
  - ICMP packets
- Protocol filtering capabilities
- Interface selection
- Detailed packet information display
- Graceful shutdown handling

## Prerequisites

- Python 3.6 or higher
- Root/Administrator privileges (required for raw socket access)
- Operating System: Linux, macOS, or Windows

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/packet-sniffer.git
cd packet-sniffer
```

2. No additional dependencies are required as the project uses only Python standard libraries.

## Usage

### Basic Usage

Run the packet sniffer with default settings:
```bash
sudo python packetSniffer.py
```

### Command Line Options

- `-i` or `--interface`: Specify the network interface to sniff on
- `-f` or `--filter`: Filter packets by protocol number
  - 1: ICMP
  - 6: TCP
  - 17: UDP

### Examples

1. Sniff on a specific interface:
```bash
sudo python packetSniffer.py -i eth0
```

2. Filter TCP packets only:
```bash
sudo python packetSniffer.py -f 6
```

3. Combine interface and protocol filter:
```bash
sudo python packetSniffer.py -i eth0 -f 17
```

## Output Format

The packet sniffer displays detailed information about each captured packet:

```
Ethernet Frame:
    Destination: XX:XX:XX:XX:XX:XX, Source: XX:XX:XX:XX:XX:XX, Protocol: 8
    IPv4 Packet:
        Version: 4, Header Length: 20, TTL: 64
        Protocol: 6, Source: 192.168.1.1, Target: 192.168.1.2
        TCP Segment:
            Source Port: 80, Destination Port: 12345
            Sequence: 123456789, Acknowledgement: 987654321
            Flags:
                URG: 0, ACK: 1, PSH: 0, RST: 0, SYN: 0, FIN: 0
            Data:
                [Packet payload in hex format]
```

## Security Note

This tool requires root/administrator privileges to capture raw network packets. Please use it responsibly and in accordance with your local network policies and regulations.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.


## Acknowledgments

- Inspired by network analysis tools and packet capture libraries
- Built using Python's socket and struct libraries

## For Feedback contact me here:
- https://linktr.ee/Fxrhan
