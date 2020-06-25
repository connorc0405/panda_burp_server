#!/usr/bin/env python3
# Present socket for Burp extension to connect to for control data.


import socket


def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', 8081))
    sock.listen()
    conn = sock.accept()

    print(conn)


if __name__ == '__main__':
    start_server()
