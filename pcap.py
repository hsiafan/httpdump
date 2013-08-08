#coding=utf-8
__author__ = 'dongliu'

import struct
import socket


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

    def __str__(self):
        return "%s:%d  -->  %s:%d, type:%d, seq:%d, ack:%s size:%d" % \
               (self.source, self.source_port, self.dest, self.dest_port, self.pac_type, self.seq,
                self.ack, len(self.body))

    def gen_key(self):
        skey = self.source + ':' + str(self.source_port)
        dkey = self.dest + ':' + str(self.dest_port)
        if cmp(skey, dkey) < 0:
            key = skey + '-' + dkey
        else:
            key = dkey + '-' + skey
        return key

    def expectAck(self):
        if self.pac_type == TcpPack.TYPE_ESTAB:
            return self.seq + len(self.body)
        else:
            return self.seq + 1


def pcapCheck(infile):
    """check the header of cap file, see it is a ledge pcap file.."""

    endian = '@'
    # read 24 bytes header
    global_head = infile.read(24)
    if not global_head:
        return False, endian

    (magic_num,) = struct.unpack('<I', global_head[0:4])
    # judge the endian of file.
    if magic_num == 0xA1B2C3D4:
        endian = '<'
    elif magic_num == 0x4D3C2B1A:
        endian = '>'
    else:
        print "not pcap format."
        return False, endian
    (version_major, version_minor, timezone, timestamp, max_package_len, linklayer)  \
            = struct.unpack(endian + '4xHHIIII', global_head)

    # now only handle Ethernet package.
    if linklayer == 1:
        #print "Ethernet"
        return True, endian
    elif linklayer == 6:
        print "TOKEN RING"
    elif linklayer == 10:
        print "FDDI"
    elif linklayer == 0:
        print "loop back"
    else:
        print linklayer

    return False


def readPcapPackage(infile):
    """ generator, read a *TCP* package once."""

    # check the header.
    flag, endian = pcapCheck(infile)
    if not flag:
        # not a valid pcap file or we cannot handle this file.
        return

    while True:
        # process one package

        # package header
        package_header = infile.read(16)
        # end of file.
        if not package_header:
            break

        (seconds, suseconds, package_len, rawlen) = struct.unpack(endian + 'IIII', package_header)
        # ethernet header
        ethernet_header = infile.read(14)
        (n_protocol, ) = struct.unpack('!12xH', ethernet_header)
        # not ip package
        if n_protocol != 2048:
            infile.seek(package_len - 14, 1)
            if n_protocol == 34525:
                # TODO: deal with ipv6 package
                pass
            continue

        # ip header
        ip_header = infile.read(20)
        (f, ip_length, protocol) = struct.unpack('!BxH5xB10x', ip_header)
        ip_header_len = (f & 0xF) * 4
        ip_version = (f >> 4) & 0xF
        # not tcp.
        if protocol != 6:
            infile.seek(package_len - 14 - 20, 1)
            continue
        source = socket.inet_ntoa(ip_header[12:16])
        dest = socket.inet_ntoa(ip_header[16:])
        if ip_header_len > 20:
            infile.seek(ip_header_len - 20, 1)

        # tcp header
        tcp_header = infile.read(20)
        (source_port, dest_port, seq, ack_seq, t_f, flags) = struct.unpack('!HHIIBB6x', tcp_header)
        tcp_header_len = ((t_f >> 4) & 0xF) * 4
        # skip extension headers
        if tcp_header_len > 20:
            infile.read(tcp_header_len - 20)
        fin = flags & 1
        syn = (flags >> 1) & 1
        rst = (flags >> 2) & 1
        psh = (flags >> 3) & 1
        ack = (flags >> 4) & 1
        urg = (flags >> 5) & 1

        body_len = package_len - 14 - ip_header_len - tcp_header_len
        body_len2 = ip_length - ip_header_len - tcp_header_len
        # body
        body = infile.read(body_len2)

        if body_len > body_len2:
            # TODO: why 6bytes zero
            infile.seek(body_len - body_len2, 1)
        if syn == 1 and ack == 0:
            # init tcp connection
            pac_type = TcpPack.TYPE_INIT
        elif syn == 1 and ack == 1:
            pac_type = TcpPack.TYPE_INIT_ACK
        elif fin == 1:
            pac_type = TcpPack.TYPE_CLOSE
        else:
            pac_type = TcpPack.TYPE_ESTAB

        pack = TcpPack(source, source_port, dest, dest_port, pac_type, seq, ack_seq, body)
        yield pack


def readPcapPackageRegular(infile):
    """
    clean up tcp packages.
    note:we abandon the last ack package after fin.
    """
    conn_dict = {}
    reverse_conn_dict = {}
    direction_dict = {}
    for pack in readPcapPackage(infile):
        key = pack.gen_key()
        if key not in conn_dict:
            conn_dict[key] = []
            reverse_conn_dict[key] = []
            direction_dict[key] = pack.source

        if pack.source == direction_dict[key]:
            hold_packs = conn_dict[key]
            fetch_packs = reverse_conn_dict[key]
            cdict = reverse_conn_dict
        else:
            hold_packs = reverse_conn_dict[key]
            fetch_packs = conn_dict[key]
            cdict = conn_dict

        hold_packs.append(pack)
        ack_packs = [ipack for ipack in fetch_packs if ipack.expectAck() <= pack.ack]
        remain_packs = [ipack for ipack in fetch_packs if ipack.expectAck() > pack.ack]
        cdict[key] = remain_packs
        for ipack in sorted(ack_packs, key=lambda x:x.seq):
            yield ipack
