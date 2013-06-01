#!/usr/bin/env python
#coding=utf-8
import util

__author__ = 'dongliu'

import getopt
import sys
from collections import OrderedDict

import pcap
import httpconn


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
                conn_dict[key] = httpconn.HttpConn(tcp_pac)
            elif tcp_pac.pac_type == 0:
                # tcp init before capature
                # if is a http request?
                if util.ishttprequest(tcp_pac.body):
                    conn_dict[key] = httpconn.HttpConn(tcp_pac)
            else:
                # ignore 
                pass
        #endfor
        for conn in conn_dict.values():
            conn.output(show_level, encoding)
    #endwhile


if __name__ == "__main__":
    main()
