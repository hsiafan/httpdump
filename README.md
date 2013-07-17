### pyhttpcap

分析和显示http请求

有两种功能:

* show_pcap.py, 解析和显示pcap文件中的http数据包内容, pcap文件可通过tcpdump等抓包软件获得, 会忽略文件中非TCP/HTTP的数据包。
* httpproxy.py, 启动一个http代理, 可以记录和显示经过此代理发送的所有http数据包

特性：

* http请求/响应按TCP连接进行分组, 复用同一TCP连接的请求在一起显示
* 显示http包的包头和包体中的文本内容
* 动处理chunked/gzip
* 动转换字符编码
* json内容进行格式化输出

### 分析pcap文件：

假设我们使用tcpdump抓包：
+ tcpdump -wtest.pcap tcp port 80

那么：
+ python ./show_pcap.py test.pcap      #仅输出请求的URL和响应状态
+ python ./show_pcap.py -v test.pcap   #输出http req/resp的头部内容
+ python ./show_pcap.py -vv test.pcap  #输出http req/resp 文本类型的包体
+ python ./show_pcap.py -vvv test.pcap  #强制输出http req/resp的包体，即使不是文本类型的内容

此外，可以使用-p, -i指定源和目标的ip/端口，这是只输出符合指定条件的数据:
+ python ./show_pcap.py -p55419 -vv test.pcap
+ python ./show_pcap.py -i192.168.109.91 -vv test.pcap

使用-e可以强制指定http包体的编码:
+ python ./show_pcap.py -i192.168.109.91 -p80 -vv -eutf-8 -vv test.pcap


### 代理模式:

+ python httpproxy.py
+ python httpproxy.py -vv                        # output http req & resp contentm, if are texts
+ python httpproxy.py -l127.0.0.1 -p8080 -vv     # the ip and port the proxy listenen on
+ python httpproxy.py -vv -ohttp.log             # ouput result to http.log


默认端口是8000, 将需要抓包的软件的代理设置为此即可.