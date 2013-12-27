#coding=utf-8

# see
#http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
#http://wiki.wireshark.org/Development/PcapNg

__author__ = 'dongliu'

import struct
import sys
from constant import *


class SectionInfo(object):
    def __init__(self):
        self.byteorder = '@'
        self.length = -1
        self.major = -1
        self.minor = -1
        self.linktype = -1
        self.capture_len = -1


def parse_section_header_block(infile, section_info, block_header):
    """get section infos from section header block"""

    # read byte order info first.
    byteorder_magic = infile.read(4)
    byteorder_magic, = struct.unpack('>I', byteorder_magic)
    if byteorder_magic == 0x1A2B3C4D:
        byteorder = '>'
    elif byteorder_magic == 0x4D3C2B1A:
        byteorder = '<'
    else:
        print >>sys.stderr, "Not a byteorder magic num:" + byteorder_magic
        return None

    block_len, = struct.unpack(byteorder + '4xI', block_header)

    # read version, should be 1, 0
    versoins = infile.read(4)
    major, minor = struct.unpack(byteorder + 'HH', versoins)

    # section len
    section_len = infile.read(8)
    section_len, = struct.unpack(byteorder + 'q', section_len)
    if section_len == -1:
        # usually did not have a known section length
        pass

    infile.seek(block_len - 12 - 16, 1)

    section_info.byteorder = byteorder
    section_info.major = major
    section_info.minor = minor
    section_info.length = section_len


def parse_interface_description_block(infile, section_info, block_len):
    # read linktype and capture size
    buf = infile.read(4)
    linktype, = struct.unpack(section_info.byteorder + 'H2x', buf)
    buf = infile.read(4)
    snap_len = struct.unpack(section_info.byteorder + 'I', buf)
    section_info.linktype = linktype
    section_info.snap_len = snap_len
    infile.seek(block_len - 12 - 8, 1)


def parse_enhanced_packet(infile, section_info, block_len):
    buf = infile.read(4)
    interface_id, = struct.unpack(section_info.byteorder + 'I', buf)

    # skip timestamp
    buf = infile.read(8)
    h_timestamp, l_timestamp = struct.unpack(section_info.byteorder + 'II', buf)
    timestamp = (h_timestamp << 32) + l_timestamp

    # capture len
    buf = infile.read(8)
    capture_len, packet_len = struct.unpack(section_info.byteorder + 'II', buf)
    padded_capture_len = ((capture_len-1)/4 + 1) * 4

    # the captured data
    data = infile.read(capture_len)

    # skip other optional fields
    infile.seek(block_len - 12 - 20 - capture_len, 1)
    return data


def parse_block(infile, section_info):
    """read and parse a block"""
    block_header = infile.read(8)
    if len(block_header) < 8:
        return None
    block_type, block_len = struct.unpack(section_info.byteorder + 'II', block_header)
    data = ''
    if block_type == BlockType.SECTION_HEADER:
        parse_section_header_block(infile, section_info, block_header)
    elif block_type == BlockType.INTERFACE_DESCRIPTOIN:
        # read linktype and capture size
        parse_interface_description_block(infile, section_info, block_len)
    elif block_type == BlockType.ENHANCED_PACKET:
        data = parse_enhanced_packet(infile, section_info, block_len)
    #TODO:add other block type we know
    else:
        infile.seek(block_len - 12, 1)
        print >> sys.stderr, "unknow block type:%s, size:%d" % (hex(block_type), block_len)

    # read anthor block_len
    block_len_t = infile.read(4)
    block_len_t, = struct.unpack(section_info.byteorder + 'I', block_len_t)
    if block_len_t != block_len:
        print >>sys.stderr, "block_len not equal, header:%d, tail:%d." % (block_len, block_len_t)
    return data


def read_packet(infile):
    section_info = SectionInfo()
    while True:
        link_packet = parse_block(infile, section_info)
        if link_packet == '':
            continue
        elif link_packet is None:
            return
        else:
            yield section_info.byteorder, section_info.linktype, link_packet