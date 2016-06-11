from __future__ import unicode_literals, print_function, division

import struct
import socket
from httpcap.constant import *
from httpcap.link_layer import LinkLayer


class TcpPack:
    """ a tcp packet, header fields and data. """

    def __init__(self, source, source_port, dest, dest_port, flags, seq, ack_seq, body, timestamp):
        self.source = source
        self.source_port = source_port
        self.dest = dest
        self.dest_port = dest_port
        self.flags = flags
        self.seq = seq
        self.ack_seq = ack_seq
        self.body = body
        self.key = None
        self.micro_second = None

        self.fin = flags & 1
        self.syn = (flags >> 1) & 1
        self.rst = (flags >> 2) & 1
        # psh = (flags >> 3) & 1
        self.ack = (flags >> 4) & 1
        # urg = (flags >> 5) & 1

        # timestamp in micro second when capture this packet
        self.timestamp = timestamp

    def __str__(self):
        return "%s:%d  -->  %s:%d, seq:%d, ack_seq:%s size:%d fin:%d syn:%d ack:%d" % \
               (self.source, self.source_port, self.dest, self.dest_port, self.seq,
                self.ack_seq, len(self.body), self.fin, self.syn, self.ack)

    def gen_key(self):
        if self.key:
            return self.key
        skey = '%s:%d' % (self.source, self.source_port)
        dkey = '%s:%d' % (self.dest, self.dest_port)
        if skey < dkey:
            self.key = skey + '-' + dkey
        else:
            self.key = dkey + '-' + skey
        return self.key

    def source_key(self):
        return '%s:%d' % (self.source, self.source_port)


# see http://en.wikipedia.org/wiki/Ethertype
def parse_ip_packet(network_protocol, ip_packet):
    # ip header
    if network_protocol == NetworkProtocol.IP or network_protocol == NetworkProtocol.PPP_IP:
        ip_base_header_len = 20
        ip_header = ip_packet[0:ip_base_header_len]
        (ip_info, ip_length, transport_protocol) = struct.unpack(b'!BxH5xB10x', ip_header)
        # real ip header len.
        ip_header_len = (ip_info & 0xF) * 4
        ip_version = (ip_info >> 4) & 0xF

        # skip all extra header fields.
        if ip_header_len > ip_base_header_len:
            pass

        source = socket.inet_ntoa(ip_header[12:16])
        dest = socket.inet_ntoa(ip_header[16:])

        return transport_protocol, source, dest, ip_packet[ip_header_len:ip_length]
    elif network_protocol == NetworkProtocol.IPV6:
        # TODO: deal with ipv6 package
        return None, None, None, None
    else:
        # skip
        return None, None, None, None


def parse_tcp_packet(tcp_packet):
    """read tcp data.http only build on tcp, so we do not need to support other protocols."""
    tcp_base_header_len = 20
    # tcp header
    tcp_header = tcp_packet[0:tcp_base_header_len]
    source_port, dest_port, seq, ack_seq, t_f, flags = struct.unpack(b'!HHIIBB6x', tcp_header)
    # real tcp header len
    tcp_header_len = ((t_f >> 4) & 0xF) * 4
    # skip extension headers
    if tcp_header_len > tcp_base_header_len:
        pass

    # body
    body = tcp_packet[tcp_header_len:]

    return source_port, dest_port, flags, seq, ack_seq, body


def parse_udp_packet(ip_body):
    udp_header = ip_body[0:8]
    source_port, dest_port, length, check_sum = struct.unpack(b'!HHHH', udp_header)
    return source_port, dest_port, ip_body[8:length]


def read_tcp_packet(produce_packet):
    """
    generator, read a *TCP* package once.
    :rtype TcpPack
    """

    for link_type, micro_second, link_packet in produce_packet:
        parse_link_layer = LinkLayer.get_link_layer_parser(link_type)
        if parse_link_layer is None:
            # skip unknown link layer packet
            continue
        network_protocol, link_layer_body = parse_link_layer(link_packet)
        if network_protocol is None or link_layer_body is None:
            continue
        transport_protocol, source, dest, ip_body = parse_ip_packet(network_protocol,
                                                                    link_layer_body)

        if transport_protocol is None:
            continue

        # tcp
        if transport_protocol == TransferProtocol.TCP:
            source_port, dest_port, flags, seq, ack_seq, body = parse_tcp_packet(ip_body)
            yield TcpPack(source, source_port, dest, dest_port, flags, seq, ack_seq, body,
                          micro_second)
        elif transport_protocol == TransferProtocol.UDP:
            # source_port, dest_port, udp_body = parse_udp_packet(ip_body)
            continue
