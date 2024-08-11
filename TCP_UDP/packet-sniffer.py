from scapy.all import sniff, IP, TCP, conf

# Function to filter and print SYN, SYN-ACK, and ACK packets
def packet_callback(packet):
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        ip_layer = packet.getlayer(IP)

        if tcp_layer.flags == "S":  # SYN
            print(f"SYN packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
        elif tcp_layer.flags == "SA":  # SYN-ACK
            print(f"SYN-ACK packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
        elif tcp_layer.flags == "A":  # ACK
            print(f"ACK packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")

# Sniffing packets on the localhost interface using layer 3 socket
print("Sniffing packets... Press Ctrl+C to stop.")
conf.L3socket = conf.L3socket
sniff(filter="tcp", prn=packet_callback, store=0)
