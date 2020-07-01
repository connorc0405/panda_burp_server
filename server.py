#!/usr/bin/env python3
# Present socket for Burp extension to connect to for control data.

import socket


from panda import Panda, blocking
import panda_messages_pb2


panda = Panda(arch='x86_64', mem='1G', qcow='/panda_resources/bionic-work.qcow2', expect_prompt=rb'root@ubuntu:.*# ', extra_args='-display none -net user,hostfwd=tcp::8080-:80 -net nic')
recording_name = 'testing_testing'


def run_server():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 8081))
    sock.listen()
    conn, addr = sock.accept()

    first_msg = receive_msg(conn)
    handle_incoming_msg(first_msg, panda)

    second_msg = receive_msg(conn)
    handle_incoming_msg(second_msg, panda)


def handle_incoming_msg(msg, panda):
    """
    React to an incoming message.
    """

    msg_type = msg.WhichOneof('type')

    if msg_type == 'command':
        handle_panda_command(msg.command, panda)
    elif msg_type == 'bytes_to_taint':
        pass
    else:
        print(f'Unimplemented BurpMessage type {msg_type}.  Ignoring.')


def handle_panda_command(command_obj, panda):
    """
    Handle the incoming PANDA command.
    """

    if command_obj.cmd_string == 'begin_record':
        panda.queue_async(execute_panda_begin_record)
        panda.run()
    elif command_obj.cmd_string == 'end_record':
        panda.queue_async(execute_panda_end_record)
        panda.run()


@blocking
def execute_panda_begin_record():
    """
    Begin PANDA recording.
    """

    print('Beginning recording...')
    print(panda.run_monitor_cmd('begin_record {}'.format(recording_name)))
    panda.stop_run()


@blocking
def execute_panda_end_record():
    """
    End PANDA recording.
    """
    print('Stopping recording...')
    print(panda.run_monitor_cmd('end_record'))
    panda.stop_run()


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


@blocking
def panda_init_helpers():
    panda.revert_sync('root')
    panda.run_serial_cmd('/root/fix_network.sh')
    print('Fixed guest network')
    panda.stop_run()


if __name__ == '__main__':
    panda.queue_async(panda_init_helpers)
    panda.run()
    run_server()
