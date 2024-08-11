import socket
import select

# Server settings
HOST = "127.0.0.1"
PORT = 9997

# Create TCP socket
tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_server.bind((HOST, PORT))
tcp_server.listen(5)
print(f"TCP Server listening on {HOST}:{PORT}")

# Create UDP socket
udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_server.bind((HOST, PORT))
print(f"UDP Server listening on {HOST}:{PORT}")

# List of sockets for select to monitor
sockets_list = [tcp_server, udp_server]

while True:
    # Use select to wait for activity on either socket
    read_sockets, _, _ = select.select(sockets_list, [], [])
    
    for notified_socket in read_sockets:
        if notified_socket == tcp_server:
            # Handle new TCP connection
            client_socket, client_address = tcp_server.accept()
            print("SYN received from", client_address)
            print("SYN-ACK sent to", client_address)
            print("ACK received from", client_address)
            sockets_list.append(client_socket)
            print(f"Accepted new TCP connection from {client_address}")
        
        elif notified_socket == udp_server:
            # Handle UDP message
            message, client_address = udp_server.recvfrom(4096)
            print(f"Received UDP message: {message.decode()} from {client_address}")
            reply_message = b"Hello, UDP Client!"
            udp_server.sendto(reply_message, client_address)
            print(f"Sent UDP reply to {client_address}")
        
        else:
            # Handle data from a TCP client
            message = notified_socket.recv(4096)
            if message:
                print(f"Received TCP message: {message.decode()} from {notified_socket.getpeername()}")
                reply_message = b"Hello, TCP Client!"
                notified_socket.send(reply_message)
                print(f"Sent TCP reply to {notified_socket.getpeername()}")
            else:
                # Close the connection if no message
                print(f"Closing connection to {notified_socket.getpeername()}")
                sockets_list.remove(notified_socket)
                notified_socket.close()
