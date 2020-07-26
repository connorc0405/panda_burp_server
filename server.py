#!/usr/bin/env python3
# Present socket for Burp extension to connect to for control data.
# TODO cmdline args


import socket
import struct

from panda import Panda, blocking
import panda_messages_pb2


panda = Panda(arch='x86_64', mem='1G', qcow='/panda_resources/bionic-work.qcow2', expect_prompt=rb'root@ubuntu:.*# ', extra_args='-display none -net user,hostfwd=tcp::8080-:80 -net nic')
recording_name = 'testing_testing2'


@blocking
def main():
    panda_init_helpers()
    run_server()


@blocking
def run_server():
    """
    Handles the lifecycle of the client's taint request.
    Enforces ordering of requests based on simple, synchronous ordering of protobufs.
    """

    # Open client connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # TODO no reuse after testing finished?
    sock.bind(('0.0.0.0', 8081))
    sock.listen(0)  # We don't need to queue connections with one user.
    conn, _ = sock.accept()

    # Wait for start_recording command
    start_rec_msg = receive_msg(conn)
    assert start_rec_msg.command.cmd_type == panda_messages_pb2.StartRecording  # Exception here!

    # Send recording_started response
    start_rec_resp_msg = panda_messages_pb2.BurpMessage()
    start_rec_resp_obj = panda_messages_pb2.Response()
    start_rec_resp_obj.resp_type = panda_messages_pb2.RecordingStarted
    start_rec_resp_msg.response.CopyFrom(start_rec_resp_obj)
    panda.run_monitor_cmd('begin_record {}'.format(recording_name))
    send_msg(start_rec_resp_msg, conn)

    # HTTP happens here but we don't see it.

    # Wait for stop_recording command
    stop_rec_msg = receive_msg(conn)
    assert stop_rec_msg.command.cmd_type == panda_messages_pb2.StopRecording  # Exception here!

    # Send recording_stopped response
    stop_rec_resp_msg = panda_messages_pb2.BurpMessage()
    stop_rec_resp_obj = panda_messages_pb2.Response()
    stop_rec_resp_obj.resp_type = panda_messages_pb2.RecordingStopped
    stop_rec_resp_msg.response.CopyFrom(stop_rec_resp_obj)
    panda.run_monitor_cmd('end_record')
    send_msg(stop_rec_resp_msg, conn)

    # Wait for taint_bytes
    taint_bytes_msg = receive_msg(conn)
    assert taint_bytes_msg.command.cmd_type == panda_messages_pb2.SetTaintBytes
    print(taint_bytes_msg.command.taint_bytes)

    # TODO run subprocess to get taint result.  can we run the subprocess while panda is still running in this process (and working on the qcow?)


    # Send taint_results
    taint_result_resp_msg = panda_messages_pb2.BurpMessage()
    taint_result_resp_obj = panda_messages_pb2.Response()
    taint_result_resp_obj.resp_type = panda_messages_pb2.ReturnTaintResult
    taint_result_obj = panda_messages_pb2.TaintResult()
    taint_result_obj.temp = 123  # TODO calculate real result
    taint_result_resp_obj.taint_result.CopyFrom(taint_result_obj)
    taint_result_resp_msg.response.CopyFrom(taint_result_resp_obj)
    send_msg(taint_result_resp_msg, conn)

    panda.stop_run()


def send_msg(msg, sock):
    """
    Send the message using the given socket.
    """
    msg_serialized = msg.SerializeToString()
    pkt_len = len(msg_serialized)
    pkt = struct.pack(f'!I{pkt_len}s', pkt_len, msg_serialized)

    send_len = len(pkt)
    sent_bytes_total = 0

    while sent_bytes_total < send_len:
        sent_bytes = sock.send(pkt[sent_bytes_total:])
        if sent_bytes == 0:  # Other host closed/closing socket
            raise Exception("Socket was closed")
        sent_bytes_total += sent_bytes


def receive_msg(sock):
    """
    Return a complete incoming message.
    """

    # Get length of message from first 4 bytes
    msg_len = int.from_bytes(sock.recv(4), 'big')

    received_data = bytearray()
    while len(received_data) < msg_len:
        new_data = sock.recv(4096)
        received_data.extend(new_data)

    pbuf_obj = panda_messages_pb2.BurpMessage()
    pbuf_obj.ParseFromString(bytes(received_data))
    return pbuf_obj


@blocking
def panda_init_helpers():
    panda.revert_sync('ipv4')
    panda.run_serial_cmd('/root/fix_network.sh')
    print('Fixed guest network')


if __name__ == '__main__':
    panda.queue_async(main)
    panda.run()
