# read and parse pcapng file
# see
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
# http://wiki.wireshark.org/Development/PcapNg
from __future__ import unicode_literals, print_function, division
import struct
import sys
from pcapparser.constant import *

__author__ = 'dongliu'


class SectionInfo(object):
    def __init__(self):
        self.byteorder = b'@'
        self.length = -1
        self.major = -1
        self.minor = -1
        self.link_type = -1
        self.capture_len = -1


class PcapngFile(object):
    def __init__(self, infile, head):
        self.infile = infile
        self.section_info = SectionInfo()
        # the first 4 byte head has been read by pcap file format checker
        self.head = head

    def parse_section_header_block(self, block_header):
        """get section info from section header block"""

        # read byte order info first.
        byteorder_magic = self.infile.read(4)
        byteorder_magic, = struct.unpack(b'>I', byteorder_magic)
        if byteorder_magic == 0x1A2B3C4D:
            byteorder = b'>'
        elif byteorder_magic == 0x4D3C2B1A:
            byteorder = b'<'
        else:
            print("Not a byteorder magic num: %d" % byteorder_magic, file=sys.stderr)
            return None

        block_len, = struct.unpack(byteorder + b'4xI', block_header)

        # read version, should be 1, 0
        versions = self.infile.read(4)
        major, minor = struct.unpack(byteorder + b'HH', versions)

        # section len
        section_len = self.infile.read(8)
        section_len, = struct.unpack(byteorder + b'q', section_len)
        if section_len == -1:
            # usually did not have a known section length
            pass

        self.infile.read(block_len - 12 - 16)

        self.section_info.byteorder = byteorder
        self.section_info.major = major
        self.section_info.minor = minor
        self.section_info.length = section_len

    def parse_interface_description_block(self, block_len):
        # read link type and capture size
        buf = self.infile.read(4)
        link_type, = struct.unpack(self.section_info.byteorder + b'H2x', buf)
        buf = self.infile.read(4)
        snap_len = struct.unpack(self.section_info.byteorder + b'I', buf)
        self.section_info.link_type = link_type
        self.section_info.snap_len = snap_len
        self.infile.read(block_len - 12 - 8)

    def parse_enhanced_packet(self, block_len):
        buf = self.infile.read(4)
        interface_id, = struct.unpack(self.section_info.byteorder + b'I', buf)

        # skip timestamp
        buf = self.infile.read(8)
        h_timestamp, l_timestamp = struct.unpack(self.section_info.byteorder + b'II', buf)

        # capture len
        buf = self.infile.read(8)
        capture_len, packet_len = struct.unpack(self.section_info.byteorder + b'II', buf)
        padded_capture_len = ((capture_len - 1) // 4 + 1) * 4

        # the captured data
        data = self.infile.read(capture_len)

        # skip other optional fields
        self.infile.read(block_len - 12 - 20 - capture_len)
        return data

    def parse_block(self):
        """read and parse a block"""
        if self.head is not None:
            block_header = self.head + self.infile.read(8 - len(self.head))
            self.head = None
        else:
            block_header = self.infile.read(8)
        if len(block_header) < 8:
            return None
        block_type, block_len = struct.unpack(self.section_info.byteorder + b'II', block_header)
        data = ''
        if block_type == BlockType.SECTION_HEADER:
            self.parse_section_header_block(block_header)
        elif block_type == BlockType.INTERFACE_DESCRIPTION:
            # read link type and capture size
            self.parse_interface_description_block(block_len)
        elif block_type == BlockType.ENHANCED_PACKET:
            data = self.parse_enhanced_packet(block_len)
        # TODO:add other block type we have know
        else:
            self.infile.read(block_len - 12)
            print("unknown block type:%s, size:%d" % (hex(block_type), block_len), file=sys.stderr)

        # read author block_len
        block_len_t = self.infile.read(4)
        block_len_t, = struct.unpack(self.section_info.byteorder + b'I', block_len_t)
        if block_len_t != block_len:
            print("block_len not equal, header:%d, tail:%d." % (block_len, block_len_t),
                  file=sys.stderr)
        return data

    def read_packet(self):
        while True:
            link_packet = self.parse_block()
            if link_packet is None:
                return
            if len(link_packet) == 0:
                continue
            yield self.section_info.byteorder, self.section_info.link_type, link_packet