import sys
import socket
import threading

HEX_FILTER = ''.join(
    [(len(repr(chr(i)))==3) and chr(i) or '.' for i in range(256)]
)

def hexdump(src, length=16, show=True):
    if isinstance(src,bytes):
        src = src.decode()
    
    results = list()
    for i in range(0, len(src), length):
        word = str(src[i:i+length])

        printable = word.translate(HEX_FILTER)
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length*3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')

        if show:
            for line in results:
                print(line)
        else:
            return results
        
def recive_from(connection):
    buffer = b""
    connection.settimeout(10)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    return buffer

import time
import random

def request_handel(buffer):
    print("\n[REQUEST] Received request:")
    print(buffer.decode())
    
    # Present modification options
    print("\nChoose a modification for the request:")
    print("1. Modify HTTP Headers")
    print("2. Log requests containing specific patterns")
    print("3. Redact sensitive data")
    print("4. Inject custom parameters")
    print("5. Simulate delay or packet loss")
    print("6. No modification")
    
    choice = input("Enter your choice (1-6): ")

    if choice == "1":
        # Modify HTTP Headers
        buffer = modify_http_headers(buffer, is_request=True)
    elif choice == "2":
        # Log request with specific patterns
        log_traffic(buffer, "password")
    elif choice == "3":
        # Redact sensitive info like API keys or tokens
        buffer = redact_data(buffer)
    elif choice == "4":
        # Inject custom parameters into the request
        buffer = inject_content(buffer, is_request=True)
    elif choice == "5":
        # Simulate delay or packet loss
        buffer = simulate_delay_or_loss(buffer)
    else:
        print("No modification applied to the request.")

    return buffer

def response_handler(buffer):
    print("\n[RESPONSE] Received response:")
    print(buffer.decode())

    # Present modification options
    print("\nChoose a modification for the response:")
    print("1. Modify HTTP Headers")
    print("2. Log responses containing specific patterns")
    print("3. Redact sensitive headers (e.g., Set-Cookie)")
    print("4. Inject custom content (e.g., HTML or JS)")
    print("5. Simulate delay or packet loss")
    print("6. No modification")

    choice = input("Enter your choice (1-6): ")

    if choice == "1":
        # Modify HTTP Headers
        buffer = modify_http_headers(buffer, is_request=False)
    elif choice == "2":
        # Log response with specific patterns
        log_traffic(buffer, "200 OK")
    elif choice == "3":
        # Redact sensitive headers
        buffer = redact_data(buffer)
    elif choice == "4":
        # Inject custom HTML or JavaScript into the response
        buffer = inject_content(buffer, is_request=False)
    elif choice == "5":
        # Simulate delay or packet loss
        buffer = simulate_delay_or_loss(buffer)
    else:
        print("No modification applied to the response.")

    return buffer

# Helper Functions for Modifications
def modify_http_headers(buffer, is_request):
    """ Modify HTTP headers based on user selection. """
    headers = buffer.decode().split("\r\n")
    
    if is_request:
        # Modify request headers (e.g., User-Agent)
        headers[0] = headers[0].replace("User-Agent", "User-Agent: Modified-Agent")
    else:
        # Modify response headers (e.g., Server)
        headers[0] = headers[0].replace("Server", "Server: Modified-Server")
    
    modified_buffer = "\r\n".join(headers).encode()
    return modified_buffer

def log_traffic(buffer, pattern):
    """ Log traffic containing a specific pattern. """
    if pattern in buffer.decode():
        print(f"Log: Detected pattern '{pattern}' in traffic:")
        print(buffer.decode())

def redact_data(buffer):
    """ Redact sensitive information from the request/response. """
    buffer_str = buffer.decode().replace("API_KEY", "[REDACTED]").replace("token", "[REDACTED]")
    return buffer_str.encode()

def inject_content(buffer, is_request):
    """ Inject custom parameters or HTML/JS into the request/response. """
    if is_request:
        buffer_str = buffer.decode() + "\r\nCustom-Parameter: InjectedValue"
    else:
        buffer_str = buffer.decode() + "<!-- Injected HTML content -->"
    
    return buffer_str.encode()

def simulate_delay_or_loss(buffer):
    """ Simulate delay or packet loss in the traffic. """
    # Randomly decide to delay or drop packets
    if random.random() < 0.1:  # 10% chance to simulate delay
        delay = random.uniform(0.5, 2.0)  # Random delay between 0.5 and 2 seconds
        print(f"Simulating a delay of {delay:.2f} seconds...")
        time.sleep(delay)
    elif random.random() < 0.05:  # 5% chance to drop the packet
        print("Simulating packet loss. Dropping the packet.")
        return b""  # Empty buffer to simulate dropped packet
    
    return buffer


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    if receive_first:
        remote_buffer = recive_from(remote_socket)

    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." %len(remote_buffer))
        client_socket.send(remote_buffer)

    while True:
        local_buffer = recive_from(client_socket)
        if len(local_buffer):
            line = "[<==] Sending %d bytes to localhost." %len(remote_buffer)
            print(line)
            hexdump(local_buffer)

            local_buffer = request_handel(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote host.")
    
        remote_buffer = recive_from(remote_socket)
        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." %len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break

def server_loop(local_host, local_port, remote_host, remote_port, receive_fist):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print('problem on bind: %r' %e)
        print('[!!] Failed to listen on %s:%d' % (local_host, local_port))
        sys.exit(0)
    
    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        # print out the local connection information
        line = "> Recived incoming connection from %s:%d" %(addr[0], addr[1])
        print(line)
        # start a thread to talk on the remote host
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_fist)
        )
        proxy_thread.start()

def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport]", end='')
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 900 10.12.132.1 9000 True")
        sys.exit(0)
    
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False
    
    server_loop(local_host, local_port,remote_host, remote_port, receive_first)

if __name__ == '__main__':
    main()
    