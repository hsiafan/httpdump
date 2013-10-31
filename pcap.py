#coding=utf-8

__author__ = 'dongliu'

import struct
import socket

#Modifier: Lonkil (lonkil#gmail.com)
#Date:   2013-10-11
#add the Link-Type (LINKTYPE_LINUX_SLL) support.


# all data-link data types: http://www.tcpdump.org/linktypes.html
class LinkLayerType:
    """support LinkType"""

    def __init__(self):
        pass

    LINKTYPE_LINUX_SLL = 113
    LINKTYPE_ETHERNET = 1


class NetworkProtocal:
    def __init__(self):
        pass

    IP = 2048
    IPV6 = 34525


class TransferProtocal:
    def __init__(self):
        pass

    TCP = 6


class TcpPack:
    """
    represent a tcp package.
    """

    TYPE_INIT = 1  # init tcp connection
    TYPE_INIT_ACK = 2
    TYPE_ESTAB = 0  # establish conn
    TYPE_CLOSE = -1  # close tcp connection

    def __init__(self, source, source_port, dest, dest_port, pac_type, seq, ack, body):
        self.source = source
        self.source_port = source_port
        self.dest = dest
        self.dest_port = dest_port
        self.pac_type = pac_type
        self.seq = seq
        self.ack = ack
        self.body = body
        self.direction = 0
        self.key = None

    def __str__(self):
        return "%s:%d  -->  %s:%d, type:%d, seq:%d, ack:%s size:%d" % \
               (self.source, self.source_port, self.dest, self.dest_port, self.pac_type, self.seq,
                self.ack, len(self.body))

    def gen_key(self):
        if self.key:
            return self.key
        skey = self.source + ':' + str(self.source_port)
        dkey = self.dest + ':' + str(self.dest_port)
        if cmp(skey, dkey) < 0:
            self.key = skey + '-' + dkey
        else:
            self.key = dkey + '-' + skey
        return self.key

    def expect_ack(self):
        if self.pac_type == TcpPack.TYPE_ESTAB:
            return self.seq + len(self.body)
        else:
            return self.seq + 1


def pcap_check(infile):
    """check the header of cap file, see it is a ledge pcap file.."""

    # default, auto
    endian = '@'
    # read 24 bytes header
    global_head = infile.read(24)
    if not global_head:
        return False, endian, -1

    (magic_num,) = struct.unpack('<I', global_head[0:4])
    # judge the endian of file.
    if magic_num == 0xA1B2C3D4:
        endian = '<'
    elif magic_num == 0x4D3C2B1A:
        endian = '>'
    else:
        return False, endian, -1

    (version_major, version_minor, timezone, timestamp, max_package_len, linklayer) \
        = struct.unpack(endian + '4xHHIIII', global_head)

    # now only handle Ethernet package.
    if linklayer == LinkLayerType.LINKTYPE_ETHERNET:
        return True, endian, LinkLayerType.LINKTYPE_ETHERNET
    elif linklayer == LinkLayerType.LINKTYPE_LINUX_SLL:
        #LINKTYPE_LINUX_SLL
        return True, endian, LinkLayerType.LINKTYPE_LINUX_SLL

    return False, endian, linklayer


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
        raise StopIteration()

    (seconds, suseconds, package_len, rawlen) = struct.unpack(byteorder + 'IIII', package_header)

    return package_len


# http://standards.ieee.org/about/get/802/802.3.html
def dl_parse_ethernet(infile, byteorder):
    """
    parse the Link type is Ethernet type
    """
    package_len = read_pcap_pac(infile, byteorder)

    eth_header_len = 14
    # ethernet header
    ethernet_header = infile.read(eth_header_len)
    if not ethernet_header:
        raise StopIteration()

    (n_protocol, ) = struct.unpack('!12xH', ethernet_header)
    return n_protocol, package_len - eth_header_len


# http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
def dl_parse_linux_sll(infile, byteorder):
    """
    parse the Link type is Ethernet type
    """

    sll_header_len = 16
    package_len = read_pcap_pac(infile, byteorder)

    #Linux cooked header
    linux_cooked = infile.read(sll_header_len)
    if not linux_cooked:
        raise StopIteration()

    (packet_type, link_type_address_type, link_type_address_len, link_type_address, link_type_ip) \
        = struct.unpack('!HHHQH', linux_cooked)
    return link_type_ip, package_len - sll_header_len


def read_dl_pac(infile, endian, linktype):
    """data link layer package"""
    if linktype == LinkLayerType.LINKTYPE_ETHERNET:
        return dl_parse_ethernet(infile, endian)
    elif linktype == LinkLayerType.LINKTYPE_LINUX_SLL:
        return dl_parse_linux_sll(infile, endian)


def read_ip_pac(infile, endian, linktype):
    # ip header
    n_protocol, package_len = read_dl_pac(infile, endian, linktype)

    if n_protocol == NetworkProtocal.IP:
        pass
    elif n_protocol == NetworkProtocal.IPV6:
        # TODO: deal with ipv6 package
        infile.seek(package_len, 1)
        return 0, package_len, None, None, None, None
    else:
        # skip
        infile.seek(package_len, 1)
        return 0, package_len, None, None, None, None

    ip_base_header_len = 20
    ip_header = infile.read(ip_base_header_len)
    if not ip_header:
        raise StopIteration()
    (ip_info, ip_length, protocol) = struct.unpack('!BxH5xB10x', ip_header)
    # real ip header len.
    ip_header_len = (ip_info & 0xF) * 4
    ip_version = (ip_info >> 4) & 0xF

    # skip all extra header fields.
    if ip_header_len > ip_base_header_len:
        infile.seek(ip_header_len - ip_base_header_len, 1)

    # not tcp, skip.
    if protocol != TransferProtocal.TCP:
        infile.seek(package_len - ip_header_len, 1)
        return 0, None, None, None, None

    source = socket.inet_ntoa(ip_header[12:16])
    dest = socket.inet_ntoa(ip_header[16:])

    return 1, package_len - ip_header_len, ip_header_len, ip_length, source, dest


def read_tcp_pac(infile, endian, linktype):
    state, package_len, ip_header_len, ip_length, source, dest = read_ip_pac(infile, endian, linktype)
    if state == 0:
        return None

    tcp_base_header_len = 20
    # tcp header
    tcp_header = infile.read(tcp_base_header_len)
    (source_port, dest_port, seq, ack_seq, t_f, flags) = struct.unpack('!HHIIBB6x', tcp_header)
    # real tcp header len
    tcp_header_len = ((t_f >> 4) & 0xF) * 4
    # skip extension headers
    if tcp_header_len > tcp_base_header_len:
        infile.read(tcp_header_len - tcp_base_header_len)

    fin = flags & 1
    syn = (flags >> 1) & 1
    rst = (flags >> 2) & 1
    psh = (flags >> 3) & 1
    ack = (flags >> 4) & 1
    urg = (flags >> 5) & 1

    body_len = package_len - tcp_header_len
    real_body_len = ip_length - ip_header_len - tcp_header_len

    # body
    body = infile.read(real_body_len)

    # skip paddings
    if body_len > real_body_len:
        infile.seek(body_len - real_body_len, 1)

    if syn == 1 and ack == 0:
        # init tcp connection
        pac_type = TcpPack.TYPE_INIT
    elif syn == 1 and ack == 1:
        pac_type = TcpPack.TYPE_INIT_ACK
    elif fin == 1:
        pac_type = TcpPack.TYPE_CLOSE
    else:
        pac_type = TcpPack.TYPE_ESTAB

    return 1, TcpPack(source, source_port, dest, dest_port, pac_type, seq, ack_seq, body)


def read_package(infile):
    """ generator, read a *TCP* package once."""

    # check the header.
    flag, endian, linktype = pcap_check(infile)
    if not flag:
        # not a valid pcap file or we cannot handle this file.
        print "can't recognize this PCAP file format.(link type: %d)" % (linktype, )
        return

    if linktype != LinkLayerType.LINKTYPE_ETHERNET and linktype != LinkLayerType.LINKTYPE_LINUX_SLL:
        print "Link layer type %d not supported." % linktype

    while True:
        state, pack = read_tcp_pac(infile, endian, linktype)

        if state == 1 and pack:
            yield pack
            continue
        else:
            continue


def read_package_r(infile):
    """
    clean up tcp packages.
    note:we abandon the last ack package after fin.
    """
    conn_dict = {}
    reverse_conn_dict = {}
    direction_dict = {}
    for pack in read_package(infile):
        key = pack.gen_key()
        if key not in conn_dict:
            conn_dict[key] = []
            reverse_conn_dict[key] = []
            direction_dict[key] = pack.source + str(pack.source_port)

        if pack.source + str(pack.source_port) == direction_dict[key]:
            hold_packs = conn_dict[key]
            fetch_packs = reverse_conn_dict[key]
            cdict = reverse_conn_dict
        else:
            hold_packs = reverse_conn_dict[key]
            fetch_packs = conn_dict[key]
            cdict = conn_dict

        if pack.body or pack.pac_type != TcpPack.TYPE_ESTAB:
            hold_packs.append(pack)
        ack_packs = [ipack for ipack in fetch_packs if ipack.expect_ack() <= pack.ack]
        remain_packs = [ipack for ipack in fetch_packs if ipack.expect_ack() > pack.ack]
        cdict[key] = remain_packs
        for ipack in sorted(ack_packs, key=lambda x: x.seq):
            yield ipack

            # TODO: add close sokect logic, and delete elements from dicts.
