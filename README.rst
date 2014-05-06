Analysis and display http request/response. Python 2.7+ / Python 3.3+
required

This can be used in two ways:

-  parse\_pcap, parse and display pcap/pcapng file http packet contents
   , pcap files can be obtained via tcpdump capture software , etc. ,
   will ignore non-TCP/non-HTTP packets.
-  proxy\_cap, start a http proxy that can record and display all http
   packets sent through this agent

Features:

-  Http request grouped by tcp connections, the requests in one
   keep-alive http connection will display together
-  Display http packet header and content with text type
-  Auto handling chunked / gzip
-  Auto handling character encoding
-  Json content / UrlEncoded content formatted output

Install
~~~~~~~

You can install this tool via pip:

::

    pip install pyhttpcap

Analysis pcap file
~~~~~~~~~~~~~~~~~~

Suppose we use tcpdump to capture packets:

::

    tcpdump -wtest.pcap tcp port 80

Then:

::

    # only display the requested URL and response status  
    parse_pcap test.pcap
    # display http req/resp headers
    parse_pcap -v test.pcap
    # display http req/resp headers and body which type is marked is text/html/xml.. and other text types in resp's headers
    parse_pcap -vv test.pcap
    # display http req/resp headers and body, as long as not being judged as binary content
    parse_pcap -vvv test.pcap
    # display and attempt to do url decoding and formatting json output
    parse_pcap -vv -b test.pcap

In addition, you can use the -p/-i to specify the ip/port of source and
destination, will only display http data meets the specified conditions:

::

    parse_pcap -p55419 -vv test.pcap
    parse_pcap -i192.168.109.91 -vv test.pcap

Use -e can forced the encoding http body used:

::

    parse_pcap -i192.168.109.91 -p80 -vv -eutf-8 test.pcap

Proxy mode
~~~~~~~~~~

::

    proxy_cap                        # start a http proxy at localhost:8000, and show urls via this proxy
    proxy_cap -vv                    # output http req & resp content, if are texts
    proxy_cap -l127.0.0.1 -p8080 -vv # the ip and port the proxy listened on
    proxy_cap -vv -ohttp.log         # output result to http.log

The default port is 8000, just set the software(browsers or something
else) 's proxy to this, the capture and parser will work.
