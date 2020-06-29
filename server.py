#!/usr/bin/env python3
# Present socket for Burp extension to connect to for control data.

import socket


import panda_messages_pb2


def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 8081))
    sock.listen()
    conn, addr = sock.accept()

    first_msg = receive_msg(conn)
    print(first_msg)


def receive_msg(sock):
    """
    Return a complete incoming message.
    """

    # Get length of message from first 4 bytes
    msg_len = int.from_bytes(sock.recv(4), 'big')

    received_data = bytearray()
    while len(received_data) < msg_len - 4:
        new_data = sock.recv(4096)
        received_data.extend(new_data)

    pbuf_obj = panda_messages_pb2.BurpMessage()
    pbuf_obj.ParseFromString(bytes(received_data))
    return pbuf_obj


if __name__ == '__main__':
    start_server()
