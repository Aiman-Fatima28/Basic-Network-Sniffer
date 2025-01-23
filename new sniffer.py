import socket
import struct
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
log = logging.getLogger()

def main():
    # Create a raw socket
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    HOST = socket.gethostbyname(socket.gethostname())
    conn.bind((HOST, 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    log.info(f"Listening on {HOST}")
    
    try:
        while True:
            raw_data, _ = conn.recvfrom(65536)
            parse_ethernet_frame(raw_data)
    except KeyboardInterrupt:
        log.info("Stopping packet sniffer.")
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

def parse_ethernet_frame(data):
    dest_mac, src_mac, eth_proto, payload = struct.unpack("! 6s 6s H", data[:14])
    dest_mac = format_mac(dest_mac)
    src_mac = format_mac(src_mac)
    eth_proto = socket.htons(eth_proto)
    log.info(f"Ethernet Frame -> Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")
    
    if eth_proto == 8:  # IPv4
        parse_ipv4_packet(payload)

def parse_ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    src_ip, dest_ip = format_ipv4(src), format_ipv4(target)
    log.info(f"IPv4 Packet -> Version: {version}, Header Length: {header_length}, TTL: {ttl}, Protocol: {proto}, Source: {src_ip}, Destination: {dest_ip}")
    
    payload = data[header_length:]
    if proto == 1:
        parse_icmp_packet(payload)
    elif proto == 6:
        parse_tcp_segment(payload)
    elif proto == 17:
        parse_udp_segment(payload)
    else:
        log.info("Unknown Protocol")

def parse_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    log.info(f"ICMP Packet -> Type: {icmp_type}, Code: {code}, Checksum: {checksum}")

def parse_tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, flags = struct.unpack("! H H L L H", data[:14])
    log.info(f"TCP Segment -> Source Port: {src_port}, Destination Port: {dest_port}, Sequence: {sequence}, Acknowledgment: {acknowledgment}")
    parse_tcp_flags(flags)

def parse_tcp_flags(flags):
    flag_urg = (flags & 32) >> 5
    flag_ack = (flags & 16) >> 4
    flag_psh = (flags & 8) >> 3
    flag_rst = (flags & 4) >> 2
    flag_syn = (flags & 2) >> 1
    flag_fin = flags & 1
    log.info(f"TCP Flags -> URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}")

def parse_udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    log.info(f"UDP Segment -> Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}")

def format_mac(mac):
    return ":".join(f"{b:02x}" for b in mac).upper()

def format_ipv4(addr):
    return ".".join(map(str, addr))

if __name__ == "__main__":
    main()
