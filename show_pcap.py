#!/usr/bin/env python
#coding=utf-8
from Queue import Queue
import argparse
import textutils

__author__ = 'dongliu'

import sys
from collections import OrderedDict

import pcap
from httpparser import HttpType, parse_http_data, OutputLevel


class HttpConn:
    """all data having same source/dest ip/port in one http connection."""

    def __init__(self, tcp_pac, level, outputfile, encoding):
        self.source_ip = tcp_pac.source
        self.source_port = tcp_pac.source_port
        self.dest_ip = tcp_pac.dest
        self.dest_port = tcp_pac.dest_port

        self.status = 0
        self.outputfile = outputfile

        self.queue = Queue()
        # start parser thread
        self.parser_worker = parse_http_data(self.queue, level, outputfile, encoding)
        self.append(tcp_pac)

    def append(self, tcp_pac):
        if len(tcp_pac.body) == 0:
            return
        if self.status == -1 or self.status == 2:
            # not http conn or conn already closed.
            return
        if tcp_pac.source == self.source_ip:
            httptype = HttpType.REQUEST
        else:
            httptype = HttpType.RESPONSE

        if tcp_pac.body:
            self.queue.put((httptype, tcp_pac.body))

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

    def finish(self):
        self.queue.put((None, None))
        self.parser_worker.join()

def print_help():
    print """Usage: python show_pcap.py [option] file
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
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_file", help="the pcap file to parse")
    parser.add_argument("-i", "--ip", help="only parse packages with specified source OR dest ip")
    parser.add_argument("-p", "--port", type=int, help="only parse packages with specified source OR dest port")
    parser.add_argument("-v", "--verbosity", help="increase output verbosity(-vv is recommended)", action="count")
    parser.add_argument("-o", "--output", help="output to file instead of stdout")
    parser.add_argument("-e", "--encoding", help="decode the data use specified encodings.")
    args = parser.parse_args()

    filepath = args.pcap_file
    port = args.port
    ip = args.ip
    if args.verbosity:
        level = args.verbosity
    else:
        level = OutputLevel.ONLY_URL
    encoding = args.encoding

    if args.output:
        outputfile = open(args.output, "w+")
    else:
        outputfile = sys.stdout

    with open(filepath) as pcap_file:
        conn_dict = OrderedDict()
        for tcp_pac in pcap.readPcapPackage(pcap_file):
            #filter
            if port is not None and tcp_pac.source_port != port and tcp_pac.dest_port != port:
                continue
            if ip is not None and tcp_pac.source != ip and tcp_pac.dest != ip:
                continue

            key = tcp_pac.gen_key()
            # we already have this conn
            if key in conn_dict:
                conn_dict[key].append(tcp_pac)
                # conn closed.
                if tcp_pac.pac_type == -1:
                    conn_dict[key].finish()
                    outputfile.flush()
                    del conn_dict[key]

            # begin tcp connection.
            elif tcp_pac.pac_type == 1:
                conn_dict[key] = HttpConn(tcp_pac, level, outputfile, encoding)
            elif tcp_pac.pac_type == 0:
                # tcp init before capature
                # if is a http request?
                if textutils.ishttprequest(tcp_pac.body):
                    conn_dict[key] = HttpConn(tcp_pac, level, outputfile, encoding)
            else:
                # ignore 
                pass

        for conn in conn_dict.values():
            conn.finish()
            outputfile.flush()

    if args.output:
        outputfile.close()

if __name__ == "__main__":
    main()
