import sys
import socket
import threading
import subprocess  # For running shell commands
import signal      # For handling stop signals
import time
import random

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

def request_handel(buffer):
    print("\n[REQUEST] Received request:")
    print(buffer.decode())
    
    # Present modification options
    print("\nChoose a modification for the request:")
    print("1. Modify Text content")
    print("2. Log requests containing specific patterns")
    print("3. No modification")
    
    choice = input("Enter your choice (1-3): ")

    if choice == "1":
        # Modify HTTP Headers
        buffer = modify_text_messages(buffer, is_request=True)
    elif choice == "2":
        # Log request with specific patterns
        log_traffic(buffer, "password")
    else:
        print("No modification applied to the request.")

    return buffer

def response_handler(buffer):
    print("\n[RESPONSE] Received response:")
    print(buffer.decode())

    # Present modification options
    print("\nChoose a modification for the response:")
    print("1. Modify Text content")
    print("2. Log responses containing specific patterns")
    print("3. No modification")

    choice = input("Enter your choice (1-3): ")

    if choice == "1":
        # Modify HTTP Headers
        buffer = modify_text_messages(buffer, is_request=False)
    elif choice == "2":
        # Log response with specific patterns
        log_traffic(buffer, "password")
    else:
        print("No modification applied to the response.")

    return buffer

# Helper Functions for Modifications
def modify_text_messages(buffer, is_request):
    data = buffer.decode('utf-8')
    
    if is_request:
        # Modify the username or password input
        if "username" in data.lower():
            data = data.replace("username", "attacker_user")
        elif "password" in data.lower():
            data = data.replace("password", "attacker_pass")
    else:
        # Modify server responses
        data = data.replace("Login Page", "Secure Login Page")
        data = data.replace("Enter password:", "Enter your secret password:")
    
    return data.encode('utf-8')

def log_traffic(buffer, pattern):
    """ Log traffic containing a specific pattern. """
    if pattern in buffer.decode():
        print(f"Log: Detected pattern '{pattern}' in traffic:")
        print(buffer.decode())


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






def add_iptables_rule():
    # Add iptables rule to redirect traffic from port 8080 to 9090
    try:
        subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING',
                        '-p', 'tcp', '--dport', '8080', '-j', 'REDIRECT', '--to-port', '9090'],
                       check=True)
        print("[*] iptables rule added: forwarding port 8080 to 9090")
    except subprocess.CalledProcessError as e:
        print(f"[!!] Failed to add iptables rule: {e}")
        sys.exit(1)

def remove_iptables_rule(remote_port, local_port):
    # Remove iptables rule to stop redirecting traffic from port 8080 to 9090
    try:
        subprocess.run(['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING',
                        '-p', 'tcp', '--dport', remote_port, '-j', 'REDIRECT', '--to-port', local_port],
                       check=True)
        print("[*] iptables rule removed")
    except subprocess.CalledProcessError as e:
        print(f"[!!] Failed to remove iptables rule: {e}")

def signal_handler(sig, frame):
    # When the proxy is stopped (CTRL+C), remove the iptables rule and exit
    print("\n[*] Proxy stopping...")
    remove_iptables_rule()
    sys.exit(0)

# Your main function
def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport]", end='')
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
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
    
    # Add the iptables rule on start
    add_iptables_rule(remote_port, local_port)
    
    # Ensure iptables rule is removed when proxy stops
    signal.signal(signal.SIGINT, signal_handler)  # Capture CTRL+C
    
    # Start the proxy (your existing server loop here)
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == '__main__':
    main()