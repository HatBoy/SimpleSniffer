# SimpleSniffer
Python版简单的Linux数据包嗅探器，目前不支持Windows系统

##主要功能
+ 1.打开保存标准的pcap数据包
+ 2.嗅探数据包
+ 3.查看数据包详情
+ 4.将单个数据包保存为PDF文件

##效果展示
###抓取数据包
![Alt Text](https://github.com/HatBoy/SimpleSniffer/blob/master/images/sniffer.png)

###查看数据包详情
![Alt Text](https://github.com/HatBoy/SimpleSniffer/blob/master/images/pcapdata.png)

###单个数据包保存为PDF
![Alt Text](https://github.com/HatBoy/SimpleSniffer/blob/master/images/pdf.png)

##安装部署过程:
+ 运行环境：Python 2.7.X
+ 操作系统：Linux (以Ubuntu 15.10为例)
+ 第三方依赖库：sudo pip install scapy PyQt4  （scapy可能还需要其他依赖库，详见scapy的官网文档）
+ 运行方式：sudo python Sniffer.py   (注意：因为涉及到底层的数据包抓取，需要root权限才能运行)

##已知Bug
该数据包嗅探器主要是利用scapy的sniff（）函数实现，需要root权限才能运行，目前没有实现数据包过滤功能，已知Bug是当双击数据包展示
数据包详情时，显示的数据是上一次双击的数据，为了获取准确的数据包详情，需要双击两次数据包。