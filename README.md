Parse and display http traffic from network device or pcap file. This is a go version of origin pcap-parser, thanks to gopacket project, this tool has simpler code base and is more efficient.

For original python implementation, [refer to httpcap on pypi](https://pypi.org/project/httpcap/).

# Install & Requirement
Build httpdump requires libpcap-dev and cgo enabled.
## libpcap
for ubuntu/debian:

```sh
sudo apt install libpcap-dev
```

for centos/redhat/fedora:

```sh
sudo yum install libpcap-devel
```

for osx:

Libpcap and header files should be available in macOS already.

## Install

```sh
go get github.com/hsiafan/httpdump
```


# Usage
httpdump can read from pcap file, or capture data from network interfaces:

```
  -device string
    	Capture packet from network device. If is any, capture all interface traffics (default "any")
  -file string
    	Read from pcap file. If not set, will capture data from network device by default
  -host string
    	Filter by request host, using wildcard match(*, ?)
  -uri string
    	Filter by request url path, using wildcard match(*, ?)
  -force
    	Force print unknown content-type http body even if it seems not to be text content
  -ip string
    	Filter by ip, if either source or target ip is matched, the packet will be processed
  -level string
    	Output level, options are: url(only url) | header(http headers) | all(headers, and textuary http body) (default "header")
  -output string
    	Write result to file [output] instead of stdout
  -port uint
    	Filter by port, if either source or target port is matched, the packet will be processed.
  -pretty
    	Try to format and prettify json content
  -status string
        Filter by response status code or code range
```

## Samples
A simple capture:

```
$ httpdump
192.168.110.48:56585  ----->  101.201.170.152:80
GET / HTTP/1.1
Host: geek.csdn.net
Connection: keep-alive
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36
DNT: 1
Accept-Encoding: gzip, deflate, sdch
Accept-Language: zh-CN,zh;q=0.8
Cookie: uuid_tt_dd=-7445280944848876972_20160309; _JQCMT_ifcookie=1; _JQCMT_browser=8cc6c51a0610de98f19cf86af0855a3e; lzstat_uv=24444940273412920400|2839507@3117794@3311294


101.201.170.152:80  <-----  192.168.110.48:56585
HTTP/1.1 200 OK
Server: openresty
Date: Tue, 31 May 2016 02:40:14 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Keep-Alive: timeout=20
Vary: Accept-Encoding
Vary: Accept-Encoding
Content-Encoding: gzip

{body size: 15482 , set level arg to all to display body content}
```

More:

```sh
# parse pcap file
sudo tcpdump -wa.pcap tcp
httpdump -file a.pcap

# capture specified device:
httpdump -device eth0

# filter by ip and/or port
httpdump -port 80  # filter by port
httpdump -ip 101.201.170.152 # filter by ip
httpdump -ip 101.201.170.152 -port 80 # filter by ip and port
```

