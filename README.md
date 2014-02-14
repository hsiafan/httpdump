### Pyhttpcap

查看[中文版本][cn_mark]

Analysis and display http request/response. need python 2.7.*

There are two functions:

* show_pcap.py, parse and display pcap/pcapng file http packet contents , pcap files can be obtained via tcpdump capture software , etc. , will ignore non-TCP/non-HTTP packets.
* httpproxy.py, start a http proxy that can record and display all http packets sent through this agent

Features:

* Http request grouped by tcp connections, the requests in one keep-alive http connection will dispay together
* Display http packet header and content with text type
* Auto handling chunked / gzip
* Auto handling character encoding
* Json content / UrlEncoded content formatted output

### Analysis pcap file

Suppose we use tcpdump capture :
+ tcpdump -wtest.pcap tcp port 80

Then:

\# only display the requested URL and response status  
python show_pcap.py test.pcap  
\# diplay http req/resp headers  
python show_pcap.py -v test.pcap   
\# display http req/resp headers and body which type is marked is text/html/xml.. in headers   
python show_pcap.py -vv test.pcap  
\# display http req/resp headers and bodys, as long as not being judged as a binary type   
python show_pcap.py -vvv test.pcap   
\# display and attempting urldecode and format json output   
python show_pcap.py -vv -b test.pcap  

In addition, you can use the -p/-i to specify the ip/port of source and destination, will only display http data meets the specified conditions:
+ python show_pcap.py -p55419 -vv test.pcap
+ python show_pcap.py -i192.168.109.91 -vv test.pcap

Use -e can forced the encoding http body used:
+ python show_pcap.py -i192.168.109.91 -p80 -vv -eutf-8 test.pcap


### Proxy mode

+ python httpproxy.py
+ python httpproxy.py -vv                    # output http req & resp contentm, if are texts
+ python httpproxy.py -l127.0.0.1 -p8080 -vv # the ip and port the proxy listenen on
+ python httpproxy.py -vv -ohttp.log         # ouput result to http.log


The default port is 8000, just set the software(browsers or something else) 's proxy to this, the capture and parser will work.


[cn_mark]: https://github.com/xiaxiaocao/pyhttpcap/blob/master/README_cn.md  "中文版本"
