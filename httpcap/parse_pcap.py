from __future__ import unicode_literals, print_function, division

import struct
import sys
from collections import OrderedDict

from httpcap import cleanups
from httpcap import config
from httpcap import packet_parser
from httpcap import pcap, pcapng, content_utils
from httpcap.constant import FileFormat
from httpcap.tcp_assembly import TcpConnection


def get_file_format(infile):
    """
    get cap file format by magic num.
    return file format and the first byte of string
    :type infile:io.BufferedReader
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


def parse_pcap_file(infile):
    """
    :type infile:io.BufferedReader
    """

    file_format, head = get_file_format(infile)
    if file_format == FileFormat.PCAP:
        return pcap.PcapFile(infile, head).read_packet()
    elif file_format == FileFormat.PCAP_NG:
        return pcapng.PcapngFile(infile, head).read_packet()
    else:
        print("unknown file format.", file=sys.stderr)
        sys.exit(1)


def run_parser(produce_packet):
    conn_dict = OrderedDict()

    def clear_connection():
        # finish connection which not close yet
        for conn in conn_dict.values():
            conn.finish()

    cleanups.register(clear_connection)
    _filter = config.get_filter()
    count = 0
    for tcp_pac in packet_parser.read_tcp_packet(produce_packet):
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
        elif content_utils.is_request(tcp_pac.body):
            # tcp init before capture, we start from a possible http request header.
            conn_dict[key] = TcpConnection(tcp_pac)

        count += 1
        if count % 100 == 0:
            # check timeout connection
            keys = []
            for k, conn in conn_dict.items():
                if tcp_pac.timestamp - conn.last_timestamp > 100 * 1000 * 100:
                    conn.finish()
                    keys.append(k)
            for k in keys:
                del conn_dict[k]

    clear_connection()
