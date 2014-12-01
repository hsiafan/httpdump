Parse and show http traffics. Python 2.7.* required.

This module contains two tools:

* parse_pcap, parse pcap/pcapng file, retrieve http data and show as text. Pcap files can be obtained via tcpdump or wireshark or other network traffic capture tools.
* proxy_cap, start a http proxy that can record and display all http packets sent through this agent.

Features:

* Http requests/responses grouped by tcp connections, the requests in one keep-alive http connection will display together.
* Managed chunked and compressed http requests/responses.
* Managed character encoding
* Formate json content to a beautiful way.

### Install
This module can be installed via pip:
```sh
pip install pycapture
```

### Parse Pcap File

Use tcpdump to capture packets:
```sh
tcpdump -wtest.pcap tcp port 80
```
Then:
```sh
# only ouput the requested URL and response status  
parse_pcap test.pcap
# output http req/resp headers
parse_pcap -v test.pcap
# output http req/resp headers and body which belong to text type
parse_pcap -vv test.pcap
# output http req/resp headers and body
parse_pcap -vvv test.pcap
# display and attempt to do url decoding and formatting json output
parse_pcap -vv -b test.pcap
```

### Filter
You can use the -p/-i to specify the ip/port of source and destination, will only display http data meets the specified conditions:
```sh
parse_pcap -p55419 -vv test.pcap
parse_pcap -i192.168.109.91 -vv test.pcap
```

### encoding
Use -e can forced the encoding http body used:
```sh
parse_pcap -i192.168.109.91 -p80 -vv -eutf-8 test.pcap
```

### Used as a Proxy
```sh
# start a http proxy at localhost:8000, and show urls via this proxy
proxy_cap
# output http req & resp content, if are texts
proxy_cap -vv
# the ip and port the proxy listened on
proxy_cap -l127.0.0.1 -p8080 -vv
# output result to http.log
proxy_cap -vv -ohttp.log
```

The default port is 8000, just set the software(browsers or something else) 's proxy to this, the capture and parser will work.

