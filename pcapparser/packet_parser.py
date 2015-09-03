from __future__ import unicode_literals, print_function, division

__author__ = 'dongliu'

import struct
import socket
from pcapparser.constant import *


class TcpPack:
    """ a tcp packet, header fields and data. """

    def __init__(self, source, source_port, dest, dest_port, flags, seq, ack_seq, body):
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
        # rst = (flags >> 2) & 1
        # psh = (flags >> 3) & 1
        self.ack = (flags >> 4) & 1
        # urg = (flags >> 5) & 1

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


# http://standards.ieee.org/about/get/802/802.3.html
def dl_parse_ethernet(link_packet):
    """ parse Ethernet packet """

    eth_header_len = 14
    # ethernet header
    ethernet_header = link_packet[0:eth_header_len]

    (network_protocol, ) = struct.unpack(b'!12xH', ethernet_header)
    if network_protocol == NetworkProtocol.P802_1Q:
        # 802.1q, we need to skip two bytes and read another two bytes to get protocol/len
        type_or_len = link_packet[eth_header_len:eth_header_len + 4]
        eth_header_len += 4
        network_protocol, = struct.unpack(b'!2xH', type_or_len)
    if network_protocol == NetworkProtocol.PPPOE_SESSION:
        # skip PPPOE SESSION Header
        eth_header_len += 8
        type_or_len = link_packet[eth_header_len - 2:eth_header_len]
        network_protocol, = struct.unpack(b'!H', type_or_len)
    if network_protocol < 1536:
        # TODO n_protocol means package len
        pass
    return network_protocol, link_packet[eth_header_len:]


# http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
def dl_parse_linux_sll(link_packet):
    """ parse linux sll packet """

    sll_header_len = 16

    # Linux cooked header
    linux_cooked = link_packet[0:sll_header_len]

    packet_type, link_type_address_type, link_type_address_len, link_type_address, n_protocol \
        = struct.unpack(b'!HHHQH', linux_cooked)
    return n_protocol, link_packet[sll_header_len:]


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


def get_link_layer_parser(link_type):
    if link_type == LinkLayerType.ETHERNET:
        return dl_parse_ethernet
    elif link_type == LinkLayerType.LINUX_SLL:
        return dl_parse_linux_sll
    else:
        return None


def parse_udp_packet(ip_body):
    udp_header = ip_body[0:8]
    source_port, dest_port, length, check_sum = struct.unpack(b'!HHHH', udp_header)
    return source_port, dest_port, ip_body[8:length]


def read_tcp_packet(read_packet):
    """ generator, read a *TCP* package once."""

    for link_type, micro_second, link_packet in read_packet():
        parse_link_layer = get_link_layer_parser(link_type)
        if parse_link_layer is None:
            # skip unknown link layer packet
            continue
        network_protocol, link_layer_body = parse_link_layer(link_packet)
        transport_protocol, source, dest, ip_body = parse_ip_packet(network_protocol, link_layer_body)

        if transport_protocol is None:
            continue

        # tcp
        if transport_protocol == TransferProtocol.TCP:
            source_port, dest_port, flags, seq, ack_seq, body = parse_tcp_packet(ip_body)
            yield TcpPack(source, source_port, dest, dest_port, flags, seq, ack_seq, body)
        elif transport_protocol == TransferProtocol.UDP:
            # source_port, dest_port, udp_body = parse_udp_packet(ip_body)
            continue
