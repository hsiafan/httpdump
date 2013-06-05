### pyhttpcap

分析和显示http请求

有两种功能:
1. 解析和显示pcap文件中的http数据包内容, pcap文件可通过tcpdump等抓包软件获得, 会忽略文件中非TCP/HTTP的数据包。
2. 作为http代理, 记录和显示经过此代理发送的所有http数据包

特点：
http请求/响应按TCP连接进行分组, 复用同一TCP连接的请求在一起显示
显示http包的包头和包体中的文本内容
自动处理chunked/gzip
自动转换字符编码
对json内容进行格式化输出

### 分析pcap文件：

假设使用tcpdump抓包：
+ tcpdump -wtest.pcap tcp port 80

那么：
+ ./pyhttp.py test.pcap    //列出所有http请求
+ ./pyhttp.py -v test.pcap    //同时输出http req/resp head
+ ./pyhttp.py -vv test.pcap   //同事输出http req/resp 文本类型的包体

此外，可以使用-p, -i指定源和目标的ip/端口，这是只输出符合指定条件的数据:
+ ./pyhttp.py -p55419 -vv test.pcap
+ ./pyhttp.py -i192.168.109.91 -vv test.pcap

使用-d输出抓到的package 信息:
+ ./pyhttp.py -p55419 -vvd test.pcap

使用-e指定http包体的编码
+ ./pyhttp.py -i192.168.109.91 -p80 -vv -eutf-8 -vv test.pcap

附带一个arm指令集的tcpdump，可用于android手机抓包.

### 作为代理使用:

+ python httpproxy.py

默认端口是8000, 将需要抓包的软件的代理设置为此即可.

在android上, root后的手机可以使用proxydroid(http://apps.wandoujia.com/search?key=org.proxydroid)来设置http代理.