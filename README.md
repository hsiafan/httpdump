Pcap-parser

[![Software License](https://img.shields.io/badge/license-BSD%202%20Clause-blue.svg)](LICENSE.txt) 

Parse and show HTTP traffic. Python 2.7.* or Python 3.3+ required.

This module parses pcap/pcapng files, retrieves HTTP data, and shows as text.
Pcap files can be obtained via tcpdump or wireshark or other network traffic capture tools.

Features:

* HTTP requests/responses grouped by TCP connections; the requests in one keep-alive http connection will display together.
* Managed chunked and compressed HTTP requests/responses.
* Managed character encoding
* Format JSON content in a beautiful way.

### Install
This module can be installed via pip:
```sh
pip install pcap-parser
```

### Parse Pcap File

Use tcpdump to capture packets:
```sh
tcpdump -wtest.pcap tcp port 80
```
Then:
```sh
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
```
Or use pipe:
```sh
sudo tcpdump -w- tcp port 80 | parse_pcap 
```

### Group
Use -g to group http request/responses: 
```sh
parse_pcap -g test.pcap
```
The result looks like:
```
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
```

### Filter
You can use the -i/-p options to specify the ip/port of source and destination and `parse_pcap` will only display HTTP data that meets the specified conditions:
```sh
parse_pcap -p55419 -vv test.pcap
parse_pcap -i192.168.109.91 -vv test.pcap
```
Use -d to specify the HTTP domain; only displays HTTP req/resp with the specified domain:
```sh
parse_pcap -dwww.baidu.com -vv test.pcap
```
Use -u to specify the HTTP uri pattern; only displays HTTP req/resp in which the url contains the specified url pattern:
```sh
parse_pcap -u/api/update -vv test.pcap
```

### Encoding
Use -e to force the encoding used for the HTTP bodies:
```sh
parse_pcap -i192.168.109.91 -p80 -vv -eutf-8 test.pcap
```
