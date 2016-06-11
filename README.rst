.. figure:: https://img.shields.io/badge/licence-Simplified%20BSD-blue.svg?style=flat
   :alt: License

   License

Httpcap (Former name pcap-parser)
---------------------------------

Capture, parse and display HTTP traffics. Python 2.7.\* or Python 3.3+
required.

This module parses pcap/pcapng files, or capture traffics from
device(with libpcap), then retrieves HTTP data, and display as text.
Pcap files can be obtained via tcpdump, wireshark or other similar
tools.

Features:

-  HTTP requests/responses grouped by TCP connections; the requests in
   one keep-alive http connection will display together.
-  Managed chunked and compressed HTTP requests/responses.
-  Managed character encoding
-  Format JSON content in a beautiful way.

Install
~~~~~~~

This module can be installed via pip:

.. code:: sh

    pip install httpcap

THen you should have tools parse-pcap and parse-live installed \* For
parsing pcap file, use parse-pcap \* For capturing and parsing traffic
from net work device, use parse-live

Usage
~~~~~

Basic usage:

.. code:: sh

    # Use tcpdump to capture packets:
    tcpdump -wtest.pcap tcp port 80
    # only output the requested URL and response status
    parse-pcap test.pcap
    # or use pipe
    sudo tcpdump -w- tcp port 80 | parse-pcap
    # parse-live need to be root. capture network device en1
    # on linux/osx ifconfig to see all network devices
    sudo parse-live en1
    # capture traffics on all devices
    sudo parse-live

Following take parse-pcap as example. parse-live works exactly same as
parse-pcap, just change file name to device name.

Output level
^^^^^^^^^^^^

Parse-pcap/parse-live only show urls by default. Use -v to display more:
Then:

.. code:: sh

    # output http req/resp headers
    parse-pcap -v test.pcap
    # output http req/resp headers and body which belong to text type
    parse-pcap -vv test.pcap
    # output http req/resp headers and body
    parse-pcap -vvv test.pcap
    # display and attempt to do url decoding and formatting json output
    parse-pcap -vvb test.pcap

Group
^^^^^

Use -g to group http request/responses:

.. code:: sh

    parse-pcap -g test.pcap

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
^^^^^^

You can use the -i/-p options to specify the ip/port of source and
destination and ``parse-pcap`` will only display HTTP data that meets
the specified conditions:

.. code:: sh

    parse-pcap -p55419 -vv test.pcap
    parse-pcap -i192.168.109.91 -vv test.pcap

Use -d to specify the HTTP domain; only displays HTTP req/resp with the
specified domain:

.. code:: sh

    parse-pcap -dwww.baidu.com -vv test.pcap

Use -u to specify the HTTP uri pattern; only displays HTTP req/resp in
which the url contains the specified url pattern:

.. code:: sh

    parse-pcap -u/api/update -vv test.pcap

Encoding
^^^^^^^^

Use -e to force the encoding used for the HTTP bodies:

.. code:: sh

    parse-pcap -i192.168.109.91 -p80 -vv -eutf-8 test.pcap
