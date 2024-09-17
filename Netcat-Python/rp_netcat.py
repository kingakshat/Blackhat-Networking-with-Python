import argparse

import socket
import shlex
import subprocess
import sys
import textwrap
import threading
# from urllib import response


class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        # print('ok')
        if self.args.listen:
            # print('ok')
            self.listen()
        else:
            # print('ok')
            self.send()

    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        # print('ok')

        if self.buffer:
            # check buffer if there is something then send it first
            self.socket.send(self.buffer)
            # print(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)    # length of received data
                    response += data.decode()
                    if recv_len < 4096:  # if received length < 4096 then terminate the loop else  continue to receive data
                        break
                if response:
                    print(response)  # print the response
                    # print('ok')
                    sys.stdin.flush()
                    # a = 
                    # flush_input()
                    sys.stdout.flush()
                    buffer = sys.stdin.read()
                    try:
                        a=input()
                    except:
                        pass
                    # import os
                    # os.system('clear')
                    buffer = input('>')  # wait for input
                    buffer += '\n'
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            print('User Terminated')
            self.socket.close()
            sys.exit()

    def listen(self):
        # print("ok")
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        # print("ok")
        while True:
            client_socket, _ = self.socket.accept()
            print(_)
            client_thread = threading.Thread(
                target=self.handle, args=(client_socket,))
            client_thread.start()

    def handle(self, client_socket):
        # print('Handle')
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output)

        elif self.args.upload:
            file_buffer = b""
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.arfs.upload, 'wb') as f:
                f.write(file_buffer)

            message = f'file saved {self.args.upload}'
            client_socket.send(message.encode())

        elif self.args.command:
            cmd_buffer = b""
            while True:
                try:
                    client_socket.send(b'NT: #>')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b""
                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()


def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    # check_output runs command on local os & returns the output from the command
    output = subprocess.check_output(
        shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()


def flush_input():
    try:
        import msvcrt
        while msvcrt.kbhit():
            msvcrt.getch()
    except ImportError:
        import sys
        from termios import tcflush, TCIOFLUSH  # for linux/unix
        tcflush(sys.stdin, TCIOFLUSH)

if __name__ == '__main__':
    # use the argparse module from the standard library to create a commanf line interface
    # print('yes')
    parser = argparse.ArgumentParser(
        description='Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Examples:
        netcat.py -t 192.168.1.108 -p 5555 -l -c # command shell
        netcat.py -t 192.168.1.108 -p 5555 -l -u=mytext.txt # upload a file
        netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\" # execute command
        echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135 # echo text to server port 135
        netcat.py -t 192.168.1.108 -p 555 # connect to server
        '''))
    parser.add_argument(
        '-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute sepified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int,
                        default=5555, help='specified port')
    parser.add_argument(
        '-t', '--target', default='192.168.1.203', help='specified IP')
    parser.add_argument(
        '-u', '--upload',  help='upload file')

    args = parser.parse_args()

    if args.listen:
        buffer = ''
    else:
        # sys.stdin.flush()
        buffer = sys.stdin.read()
        # buffer="end"


nc = NetCat(args, buffer.encode())
nc.run()
