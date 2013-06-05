#!/usr/bin/env python
#coding=utf-8
import textutils

__author__ = 'dongliu'

import getopt
import sys
from collections import OrderedDict

import pcap
from httpparser import (HttpDataReader, read_request, read_response)


class HttpConn:
    """all data having same source/dest ip/port in one http connection."""

    def __init__(self, tcp_pac):
        self.source_ip = tcp_pac.source
        self.source_port = tcp_pac.source_port
        self.dest_ip = tcp_pac.dest
        self.dest_port = tcp_pac.dest_port
        self.pac_list = []
        if len(tcp_pac.body) > 0:
            self.pac_list.append(tcp_pac)
        self.status = 0

    def append(self, tcp_pac):
        if len(tcp_pac.body) == 0:
            return
        if self.status == -1 or self.status == 2:
            # not http conn or conn already closed.
            return
        if tcp_pac.source != self.source_ip:
            tcp_pac.direction = 1

        self.pac_list.append(tcp_pac)

        if self.status == 0:
            if tcp_pac.body != '':
                if textutils.ishttprequest(tcp_pac.body):
                    self.status = 1
        if tcp_pac.pac_type == -1:
            # end of connection
            if self.status == 1:
                self.status = 2
            else:
                self.status = -2

    def output(self, level, encoding):
        if self.status <= -1:
            return
        elif self.status == 0:
            return
        elif self.status == 1:
            pass
        elif self.status == 2:
            pass
        print self.source_ip, ':', self.source_port, "--- -- - >", self.dest_ip, ':', self.dest_port

        request_pacs = []
        response_pacs = []
        state = 0
        for pac in self.pac_list:
            if len(pac.body) == 0:
                continue
            if state == 0:
                if pac.direction == 1:
                    read_request(self._wrap(request_pacs), level, encoding)
                    state = 1
                    response_pacs.append(pac)
                    del request_pacs[:]
                else:
                    request_pacs.append(pac)
            else:
                if pac.direction == 0:
                    read_response(self._wrap(response_pacs), level, encoding)
                    state = 0
                    request_pacs.append(pac)
                    del response_pacs[:]
                else:
                    response_pacs.append(pac)

        if len(request_pacs) > 0:
            read_request(self._wrap(request_pacs), level, encoding)
        if len(response_pacs) > 0:
            read_response(self._wrap(response_pacs), level, encoding)

        print ''

    def _wrap(self, pacs):
        pacs.sort(key=lambda x: x.seq)
        #TODO: handle with tcp retransmission
        body = ''.join([p.body for p in pacs])
        reader = HttpDataReader(body)
        return reader


def print_help():
    print """Usage: pyhttp [option] file
    Options:
    -v      : show request/response headers
    -vv     : show text request/response bodys
    -vvv    : show all request/response bodys
    -d      : debug output.show package infos
    -h      : show helps
    -p port : only parser tcp packages with port(dest or source)
    -i ip   : only parser tcp packages with ip(dest or source)
    -e encoding : specify encoding to decode http response. auto detect if not specified.
    """


def main():
    port = -1
    ip = ''
    show_level = 0
    encoding = ''
    debug = False
    opts, args = getopt.getopt(sys.argv[1:],'hvdp:i:e:')
    for opt in opts:
        if opt[0] == '-v':
            show_level += 1
        elif opt[0] == '-h':
            print_help()
            return
        elif opt[0] == '-p':
            port = int(opt[1])
        elif opt[0] == '-i':
            ip = opt[1]
        elif opt[0] == '-e':
            encoding = opt[1]
        elif opt[0] == '-d':
            debug = True

    filepath = args[0]

    with open(filepath) as pcap_file:
        conn_dict = OrderedDict()
        for tcp_pac in pcap.readPcapPackage(pcap_file):

            #filter
            if port != -1 and tcp_pac.source_port != port and tcp_pac.dest_port != port:
                continue
            if ip != '' and tcp_pac.source != ip and tcp_pac.dest != ip:
                continue
            if debug:
                print str(tcp_pac)

            key = tcp_pac.gen_key()
            # we already have this conn
            if key in conn_dict:
                conn_dict[key].append(tcp_pac)
                # conn closed.
                if tcp_pac.pac_type == -1:
                    conn_dict[key].output(show_level, encoding)
                    del conn_dict[key]

            # begin tcp connection.
            elif tcp_pac.pac_type == 1:
                conn_dict[key] = HttpConn(tcp_pac)
            elif tcp_pac.pac_type == 0:
                # tcp init before capature
                # if is a http request?
                if textutils.ishttprequest(tcp_pac.body):
                    conn_dict[key] = HttpConn(tcp_pac)
            else:
                # ignore 
                pass

        for conn in conn_dict.values():
            conn.output(show_level, encoding)


if __name__ == "__main__":
    main()
