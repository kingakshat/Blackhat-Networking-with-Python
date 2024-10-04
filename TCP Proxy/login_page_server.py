import socket
import threading

# Define login credentials
VALID_USERNAME = "user"
VALID_PASSWORD = "pass123"

def handle_client(client_socket):
    # Send a welcome message
    client_socket.send(b"Welcome to the Login Page\n")

    # Ask for username
    client_socket.send(b"Enter username: ")
    username = client_socket.recv(1024).decode().strip()

    # Ask for password
    client_socket.send(b"Enter password: ")
    password = client_socket.recv(1024).decode().strip()

    # Check if the credentials are correct
    if username == VALID_USERNAME and password == VALID_PASSWORD:
        client_socket.send(b"Login successful! Welcome to the system.\n")
    else:
        client_socket.send(b"Login failed! Invalid credentials.\n")

    # Close the connection
    client_socket.close()

def server_loop(local_host, local_port):
    # Create a socket object
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind to the local host and port
    server.bind((local_host, local_port))
    
    # Listen for incoming connections
    server.listen(5)
    print(f"[*] Listening on {local_host}:{local_port}")

    while True:
        # Accept incoming client connections
        client_socket, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

        # Start a new thread to handle the client
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    # Define the server address and port
    local_host = "127.0.0.1"
    local_port = 8080
    
    # Start the server
    server_loop(local_host, local_port)
