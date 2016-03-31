from __future__ import unicode_literals, print_function, division
from collections import OrderedDict
import struct
import sys

from pcapparser import packet_parser
from pcapparser import pcap, pcapng, utils
from pcapparser.constant import FileFormat
from pcapparser.printer import HttpPrinter
from pcapparser.httpparser import HttpType, HttpParser
from pcapparser import config
from pcapparser.packet_parser import TcpPack
from pcapparser.utils import is_request


def get_file_format(infile):
    """
    get cap file format by magic num.
    return file format and the first byte of string
    :type infile:file
    """
    buf = infile.read(4)
    if len(buf) == 0:
        # EOF
        print("empty file", file=sys.stderr)
        sys.exit(-1)
    if len(buf) < 4:
        print("file too small", file=sys.stderr)
        sys.exit(-1)
    magic_num, = struct.unpack(b'<I', buf)
    if magic_num == 0xA1B2C3D4 or magic_num == 0xD4C3B2A1:
        return FileFormat.PCAP, buf
    elif magic_num == 0x0A0D0D0A:
        return FileFormat.PCAP_NG, buf
    else:
        return FileFormat.UNKNOWN, buf


class Stream(object):
    def __init__(self):
        self.receive_buf = []
        self.status = 0
        self.last_ack_seq = 0

    def append_packet(self, packet):
        """
        :type packet:TcpPack
        """
        if packet.seq >= self.last_ack_seq and packet.body:
            self.receive_buf.append(packet)

    def retrieve_packet(self, ack_seq):
        if ack_seq <= self.last_ack_seq:
            return None

        self.last_ack_seq = ack_seq
        data = []
        new_buf = []
        for packet in self.receive_buf:
            if packet.seq < ack_seq:
                data.append(packet)
            else:
                new_buf.append(packet)
        self.receive_buf = new_buf
        if len(data) <= 1:
            return data
        data.sort(key=lambda pct: pct.seq)
        new_data = []
        last_packet_seq = None
        for packet in data:
            if packet.seq != last_packet_seq:
                last_packet_seq = packet.seq
                new_data.append(packet)
        return new_data


class TcpConnection(object):
    def __init__(self, packet):
        """
        :type packet: TcpPack
        """
        self.up_stream = Stream()
        self.down_stream = Stream()
        self.client_key = packet.source_key()

        self.is_http = None
        self.processor = HttpPrinter((packet.source, packet.source_port),
                                     (packet.dest, packet.dest_port))
        self.http_parser = HttpParser(self.processor)
        self.on_packet(packet)

    def on_packet(self, packet):
        """
        :type packet: TcpPack
        """
        if self.is_http is None and packet.body:
            self.is_http = is_request(packet.body)

        if self.is_http == False:
            return

        if packet.source_key() == self.client_key:
            send_stream = self.up_stream
            confirm_stream = self.down_stream
            pac_type = HttpType.RESPONSE
        else:
            send_stream = self.down_stream
            confirm_stream = self.up_stream
            pac_type = HttpType.REQUEST

        if len(packet.body) > 0:
            send_stream.append_packet(packet)
        if packet.syn:
            pass
        if packet.ack:
            packets = confirm_stream.retrieve_packet(packet.ack_seq)
            if packets:
                for packet in packets:
                    self.http_parser.send(pac_type, packet.body)
        if packet.fin:
            send_stream.status = 1

    def closed(self):
        return self.up_stream.status == 1 and self.down_stream.status == 1

    def finish(self):
        self.http_parser.finish()


def parse_pcap_file(infile):
    """
    :type infile:file
    """

    conn_dict = OrderedDict()

    file_format, head = get_file_format(infile)
    if file_format == FileFormat.PCAP:
        pcap_file = pcap.PcapFile(infile, head).read_packet
    elif file_format == FileFormat.PCAP_NG:
        pcap_file = pcapng.PcapngFile(infile, head).read_packet
    else:
        print("unknown file format.", file=sys.stderr)
        sys.exit(1)

    _filter = config.get_filter()
    for tcp_pac in packet_parser.read_tcp_packet(pcap_file):
        # filter
        if not (_filter.by_ip(tcp_pac.source) or _filter.by_ip(tcp_pac.dest)):
            continue
        if not (_filter.by_port(tcp_pac.source_port) or _filter.by_port(tcp_pac.dest_port)):
            continue

        key = tcp_pac.gen_key()
        # we already have this conn
        if key in conn_dict:
            conn_dict[key].on_packet(tcp_pac)
            # conn closed.
            if conn_dict[key].closed():
                conn_dict[key].finish()
                del conn_dict[key]

        # begin tcp connection.
        elif tcp_pac.syn and not tcp_pac.ack:
            conn_dict[key] = TcpConnection(tcp_pac)
        elif utils.is_request(tcp_pac.body):
            # tcp init before capture, we start from a possible http request header.
            conn_dict[key] = TcpConnection(tcp_pac)

    # finish connection which not close yet
    for conn in conn_dict.values():
        conn.finish()