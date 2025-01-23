import socket

def basic_sniffer():
    # Create a raw socket to capture all network packets
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    
    # Bind to the local host
    host = socket.gethostbyname(socket.gethostname())
    sniffer.bind((host, 0))
    
    # Include IP headers
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    # Put the NIC into promiscuous mode (Windows only; Linux does this automatically)
    try:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except AttributeError:
        pass  # Skip for non-Windows systems
    
    print(f"Sniffer started on {host}. Press Ctrl+C to stop.")
    try:
        while True:
            # Receive packets
            packet, addr = sniffer.recvfrom(65565)
            print(f"Packet from {addr}: {packet[:20]}")
    except KeyboardInterrupt:
        print("\nStopping sniffer.")
        # Disable promiscuous mode (Windows only)
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except AttributeError:
            pass

if __name__ == "__main__":
    basic_sniffer()
