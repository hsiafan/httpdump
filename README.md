[![](https://travis-ci.org/caoqianli/httpcap.svg)](https://travis-ci.org/caoqianli/httpcap)
![License](https://img.shields.io/badge/licence-Simplified%20BSD-blue.svg?style=flat)

Parse and display http traffic from network device or pcap file. This is a go version of origin python [pcap-parser](https://github.com/caoqianli/httpcap/tree/pcap-parser), thanks to gopacket project, this tool has simpler code base and is more efficient.

# install & requirement
Build httpcap requires libpcap-dev and cgo enabled.
```sh
go get github.com/caoqianli/httpcap
```
To install libpcap-dev:
for ubuntu/debian:
```sh
sudo apt-get install libpcap-dev
```
for centos/redhat:
```sh
sudo yum install libpcap-devel
```

# Usage
httpcap can read from pcap file, or capture data from network interfaces:
```
  -device string
    	Which network interface to capture. If any, capture all interface traffics (default "any")
  -file string
    	Read from pcap file.  With file parameter specified, not not capture from network devices
  -filter string
    	filter by ip/port, format: [ip][:port], eg: 192.168.122.46:50792, 192.168.122.46, :50792
  -forcePrint
    	print http body even if it seems not to be text content
  -level string
    	Print level, url | header | all (default "header")
```
