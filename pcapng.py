#coding=utf-8

# read and parse pcapng file
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


class PcapNgFile(object):

    def __init__(self, infile):
        self.infile = infile
        self.section_info = SectionInfo()

    def parse_section_header_block(self, block_header):
        """get section infos from section header block"""

        # read byte order info first.
        byteorder_magic = self.infile.read(4)
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
        versoins = self.infile.read(4)
        major, minor = struct.unpack(byteorder + 'HH', versoins)

        # section len
        section_len = self.infile.read(8)
        section_len, = struct.unpack(byteorder + 'q', section_len)
        if section_len == -1:
            # usually did not have a known section length
            pass

        self.infile.seek(block_len - 12 - 16, 1)

        self.section_info.byteorder = byteorder
        self.section_info.major = major
        self.section_info.minor = minor
        self.section_info.length = section_len

    def parse_interface_description_block(self, block_len):
        # read linktype and capture size
        buf = self.infile.read(4)
        linktype, = struct.unpack(self.section_info.byteorder + 'H2x', buf)
        buf = self.infile.read(4)
        snap_len = struct.unpack(self.section_info.byteorder + 'I', buf)
        self.section_info.linktype = linktype
        self.section_info.snap_len = snap_len
        self.infile.seek(block_len - 12 - 8, 1)

    def parse_enhanced_packet(self, block_len):
        buf = self.infile.read(4)
        interface_id, = struct.unpack(self.section_info.byteorder + 'I', buf)

        # skip timestamp
        buf = self.infile.read(8)
        h_timestamp, l_timestamp = struct.unpack(self.section_info.byteorder + 'II', buf)
        timestamp = (h_timestamp << 32) + l_timestamp

        # capture len
        buf = self.infile.read(8)
        capture_len, packet_len = struct.unpack(self.section_info.byteorder + 'II', buf)
        padded_capture_len = ((capture_len-1)/4 + 1) * 4

        # the captured data
        data = self.infile.read(capture_len)

        # skip other optional fields
        self.infile.seek(block_len - 12 - 20 - capture_len, 1)
        return data

    def parse_block(self):
        """read and parse a block"""
        block_header = self.infile.read(8)
        if len(block_header) < 8:
            return None
        block_type, block_len = struct.unpack(self.section_info.byteorder + 'II', block_header)
        data = ''
        if block_type == BlockType.SECTION_HEADER:
            self.parse_section_header_block(block_header)
        elif block_type == BlockType.INTERFACE_DESCRIPTOIN:
            # read linktype and capture size
            self.parse_interface_description_block(block_len)
        elif block_type == BlockType.ENHANCED_PACKET:
            data = self.parse_enhanced_packet(block_len)
        #TODO:add other block type we have know
        else:
            self.infile.seek(block_len - 12, 1)
            print >> sys.stderr, "unknow block type:%s, size:%d" % (hex(block_type), block_len)

        # read anthor block_len
        block_len_t = self.infile.read(4)
        block_len_t, = struct.unpack(self.section_info.byteorder + 'I', block_len_t)
        if block_len_t != block_len:
            print >>sys.stderr, "block_len not equal, header:%d, tail:%d." % (block_len, block_len_t)
        return data

    def read_packet(self):
        while True:
            link_packet = self.parse_block()
            if link_packet == '':
                continue
            elif link_packet is None:
                return
            else:
                yield self.section_info.byteorder, self.section_info.linktype, link_packet