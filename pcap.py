#coding=utf-8
#see http://wiki.wireshark.org/Development/LibpcapFileFormat
import sys

__author__ = 'dongliu'

import struct


# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
def pcap_check(infile):
    """check the header of cap file, see it is a ledge pcap file.."""

    # default, auto
    endian = '@'
    # read 24 bytes header
    pcap_file_header_len = 24
    global_head = infile.read(pcap_file_header_len)
    if not global_head:
        raise StopIteration()

    magic_num, = struct.unpack('<I', global_head[0:4])
    # judge the endian of file.
    if magic_num == 0xA1B2C3D4:
        endian = '<'
    elif magic_num == 0x4D3C2B1A:
        endian = '>'
    else:
        return False, endian, -1

    version_major, version_minor, timezone, timestamp, max_package_len, linklayer\
        = struct.unpack(endian + '4xHHIIII', global_head)

    return True, endian, linklayer


def read_pcap_pac(infile, byteorder):
    """
    read pcap header.
    return the total package length.
    """
    # package header
    pcap_header_len = 16
    package_header = infile.read(pcap_header_len)

    # end of file.
    if not package_header:
        return None, None

    seconds, suseconds, packet_len, rawlen = struct.unpack(byteorder + 'IIII', package_header)
    # note: packet_len contains paddings.
    link_packet = infile.read(packet_len)
    if len(link_packet) < packet_len:
        return None, None
    return packet_len, link_packet


def read_packet(infile):
    flag, byteorder, linktype = pcap_check(infile)
    if not flag:
        # not a valid pcap file or we cannot handle this file.
        print >>sys.stderr, "Can't recognize this PCAP file format."
        return
    while True:
        packet_len, link_packet = read_pcap_pac(infile, byteorder)
        if link_packet:
            yield byteorder, linktype, link_packet
        else:
            return