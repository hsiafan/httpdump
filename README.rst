Parse and show http traffics. Python 2.7.\* or Python 3.3+ required.

This module parse pcap/pcapng file, retrieve http data and show as text.
Pcap files can be obtained via tcpdump or wireshark or other network
traffic capture tools.

Features:

-  Http requests/responses grouped by tcp connections, the requests in
   one keep-alive http connection will display together.
-  Managed chunked and compressed http requests/responses.
-  Managed character encoding
-  Format json content to a beautiful way.

Install
~~~~~~~

This module can be installed via pip:

.. code:: sh

    pip install pcap-parser

Parse Pcap File
~~~~~~~~~~~~~~~

Use tcpdump to capture packets:

.. code:: sh

    tcpdump -wtest.pcap tcp port 80

Then:

.. code:: sh

    # only output the requested URL and response status
    parse_pcap test.pcap
    # output http req/resp headers
    parse_pcap -v test.pcap
    # output http req/resp headers and body which belong to text type
    parse_pcap -vv test.pcap
    # output http req/resp headers and body
    parse_pcap -vvv test.pcap
    # display and attempt to do url decoding and formatting json output
    parse_pcap -vvb test.pcap

Or use pipe:

.. code:: sh

    sudo tcpdump -w- tcp port 80 | parse_pcap 

Group
~~~~~

Use -g to group http request/response:

.. code:: sh

    parse_pcap -g test.pcap

The result looks like:

::

    ********** [10.66.133.90:56240] -- -- --> [220.181.90.13:80] **********
    GET http://s1.rr.itc.cn/w/u/0/20120611181946_24.jpg
    HTTP/1.1 200 OK
    GET http://s1.rr.itc.cn/p/images/imgloading.jpg
    HTTP/1.1 200 OK
    GET http://s1.rr.itc.cn/w/u/0/20130201103132_66.png
    HTTP/1.1 200 OK
    GET http://s1.rr.itc.cn/w/u/0/20120719174136_77.png
    HTTP/1.1 200 OK
    GET http://s1.rr.itc.cn/p/images/pic_prev_open.png
    HTTP/1.1 200 OK

    ********** [10.66.133.90:47526] -- -- --> [220.181.90.13:80] **********
    GET http://s1.rr.itc.cn/w/u/0/20130227132442_43.png
    HTTP/1.1 200 OK
    GET http://s1.rr.itc.cn/p/images/pic_next.png
    HTTP/1.1 200 OK
    GET http://s1.rr.itc.cn/p/images/pic_prev.png
    HTTP/1.1 200 OK
    GET http://s1.rr.itc.cn/p/images/pic_next_open.png
    HTTP/1.1 200 OK

Filter
~~~~~~

You can use the -p/-i to specify the ip/port of source and destination,
will only display http data meets the specified conditions:

.. code:: sh

    parse_pcap -p55419 -vv test.pcap
    parse_pcap -i192.168.109.91 -vv test.pcap

Use -d to specify the http domain, only display http req/resp with the
domain:

.. code:: sh

    parse_pcap -dwww.baidu.com -vv test.pcap

Use -u to specify the http uri pattern, only dispay http req/resp which
url contains the url pattern:

.. code:: sh

    parse_pcap -u/api/update -vv test.pcap

Encoding
~~~~~~~~

Use -e can forced the encoding http body used:

.. code:: sh

    parse_pcap -i192.168.109.91 -p80 -vv -eutf-8 test.pcap
