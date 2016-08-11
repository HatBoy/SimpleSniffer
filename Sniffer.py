#!/usr/bin/env python
# coding=UTF-8
__author__ = 'dj'

import sys
from PyQt4 import QtGui, QtCore
import socket
import fcntl
import struct
from scapy.all import *
import threading
import tempfile

QtCore.QTextCodec.setCodecForTr(QtCore.QTextCodec.codecForName('utf8'))
IFACE = 'eth0'   #网卡名称
STOP = True      #停止嗅探
PACKETS = []     #数据包收集序列
SELECT_ROW = 0   #选择的行
SELECT_INFO = '' #选择行的详细信息
SHOW2STR = ''   #show2()显示的字符串
HEXSTR = ''     #hex()显示的信息
FILTER = None   #过滤规则

#主界面
class SnifferUI(QtGui.QMainWindow):
    def __init__(self, parent=None):
        QtGui.QMainWindow.__init__(self, parent)
        self.setWindowTitle(u'网络嗅探器')
        self.resize(700, 650)
        self.setWindowIcon(QtGui.QIcon('icons/logo.ico'))
        screen = QtGui.QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)
        self.initUI()

    def initUI(self):
        #工具栏
        #打开文件
        self.open_toolbar = QtGui.QAction(QtGui.QIcon('icons/open.png'), u'打开', self)
        self.open_toolbar.setShortcut('Ctrl+O')
        self.open_toolbar.triggered.connect(self.open_pcap)
        self.toolbar = self.addToolBar(u'打开')
        self.toolbar.addAction(self.open_toolbar)
        #保存
        self.save_toolbar = QtGui.QAction(QtGui.QIcon('icons/save.png'), u'保存', self)
        self.save_toolbar.setShortcut('Ctrl+S')
        self.save_toolbar.triggered.connect(self.save_pcap)
        self.toolbar = self.addToolBar(u'保存')
        self.toolbar.addAction(self.save_toolbar)
        #选择接口
        self.conf_toolbar = QtGui.QAction(QtGui.QIcon('icons/iface.png'), u'配置', self)
        self.conf_toolbar.setShortcut('Ctrl+I')
        self.conf_toolbar.triggered.connect(self.select_iface)
        self.toolbar = self.addToolBar(u'配置')
        self.toolbar.addAction(self.conf_toolbar)
        #开始嗅探
        self.start_toolbar = QtGui.QAction(QtGui.QIcon('icons/start.jpg'), u'开始', self)
        self.start_toolbar.triggered.connect(self.start_sniff)
        self.toolbar = self.addToolBar(u'开始')
        self.toolbar.addAction(self.start_toolbar)
        #停止嗅探
        self.stop_toolbar = QtGui.QAction(QtGui.QIcon('icons/stop.png'), u'停止', self)
        self.stop_toolbar.triggered.connect(self.stop_sniff)
        self.toolbar = self.addToolBar(u'停止')
        self.toolbar.addAction(self.stop_toolbar)
        #重新嗅探
        """
        self.restart_toolbar = QtGui.QAction(QtGui.QIcon('icons/restart.png'), u'重新开始', self)
        self.restart_toolbar.triggered.connect(self.restart_sniff)
        self.toolbar = self.addToolBar(u'重新开始')
        self.toolbar.addAction(self.restart_toolbar)
        """
        #过滤器
        self.filter_toolbar = QtGui.QAction(QtGui.QIcon('icons/filter.png'), u'过滤', self)
        self.filter_toolbar.triggered.connect(self.filter_pcap)
        self.toolbar = self.addToolBar(u'过滤')
        self.toolbar.addAction(self.filter_toolbar)
        #帮助
        self.help_toolbar = QtGui.QAction(QtGui.QIcon('icons/help.png'), u'帮助', self)
        self.help_toolbar.triggered.connect(self.help_me)
        self.toolbar = self.addToolBar(u'帮助')
        self.toolbar.addAction(self.help_toolbar)
        #关于
        self.about_toolbar = QtGui.QAction(QtGui.QIcon('icons/info.png'), u'关于', self)
        self.about_toolbar.triggered.connect(self.about_me)
        self.toolbar = self.addToolBar(u'关于')
        self.toolbar.addAction(self.about_toolbar)
        #退出
        self.exit_toolbar = QtGui.QAction(QtGui.QIcon('icons/exit.ico'), u'退出', self)
        self.connect(self.exit_toolbar, QtCore.SIGNAL('triggered()'), QtCore.SLOT('close()'))
        self.toolbar = self.addToolBar(u'退出')
        self.toolbar.addAction(self.exit_toolbar)
        #数据包显示栏
        self.packet_table = Packet_TableView(parent=self)
        self.packet_table.doubleClicked.connect(self.get_row_info)
        #分割栏目
        self.splitter = QtGui.QSplitter(self)
        self.splitter.addWidget(self.packet_table)
        self.splitter.setOrientation(QtCore.Qt.Vertical)
        self.setCentralWidget(self.splitter)

    def get_row_info(self):
        infoUI = ShowInfoUI(parent=self)
        infoUI.show()
        infoUI.exec_()

    #打开数据包
    def open_pcap(self):
        global PACKETS
        open_name = QtGui.QFileDialog.getOpenFileName(self, self.tr('Open Packets'), '.', self.tr("Packets Files(*.pcap *.cap)"))
        name = str(open_name)
        pcap = rdpcap(name)
        PACKETS = list(pcap)
        for packet in PACKETS:
            if int(packet.getlayer(Ether).type) == 34525 and STOP:
                proto = 'IPv6'
                src = str(packet.getlayer(IPv6).src)
                dst = str(packet.getlayer(IPv6).dst)
                info = str(packet.summary())
                self.packet_table.row_append(src, dst, proto, info)
            elif int(packet.getlayer(Ether).type) == 2048 and STOP:
                if int(packet.getlayer(IP).proto) == 6:
                    proto = 'TCP'
                elif int(packet.getlayer(IP).proto) == 17:
                    proto = 'UDP'
                elif int(packet.getlayer(IP).proto) == 1:
                    proto = 'ICMP'
                src = str(packet.getlayer(IP).src)
                dst = str(packet.getlayer(IP).dst)
                info = str(packet.summary())
                self.packet_table.row_append(src, dst, proto, info)
            elif int(packet.getlayer(Ether).type) == 2054 and STOP:
                proto = 'ARP'
                src = str(packet.getlayer(ARP).psrc)
                dst = str(packet.getlayer(ARP).pdst)
                info = str(packet.summary())
                self.packet_table.row_append(src, dst, proto, info)
            else:
                pass

    #保存数据包
    def save_pcap(self):
        save_name = QtGui.QFileDialog.getSaveFileName(self, self.tr("Save Packets"), '.', self.tr("Packets Files(*.pcap)"))
        if save_name:
            name = str(save_name + '.pcap')
            wrpcap(name, PACKETS)
            QtGui.QMessageBox.information(self, u"保存成功", self.tr("数据包保存成功!"))

    #选择网卡
    def select_iface(self):
        iface = IfaceUI(parent=self)
        iface.exec_()

    #处理数据包
    def handle_packets(self, packet):
        if int(packet.getlayer(Ether).type) == 34525 and STOP:
            proto = 'IPv6'
            src = str(packet.getlayer(IPv6).src)
            dst = str(packet.getlayer(IPv6).dst)
            info = str(packet.summary())
            self.packet_table.row_append(src, dst, proto, info)
            PACKETS.append(packet)
        elif int(packet.getlayer(Ether).type) == 2048 and STOP:
            if int(packet.getlayer(IP).proto) == 6:
                proto = 'TCP'
            elif int(packet.getlayer(IP).proto) == 17:
                proto = 'UDP'
            elif int(packet.getlayer(IP).proto) == 1:
                proto = 'ICMP'
            src = str(packet.getlayer(IP).src)
            dst = str(packet.getlayer(IP).dst)
            info = str(packet.summary())
            self.packet_table.row_append(src, dst, proto, info)
            PACKETS.append(packet)
        elif int(packet.getlayer(Ether).type) == 2054 and STOP:
            proto = 'ARP'
            src = str(packet.getlayer(ARP).psrc)
            dst = str(packet.getlayer(ARP).pdst)
            info = str(packet.summary())
            self.packet_table.row_append(src, dst, proto, info)
            PACKETS.append(packet)
        else:
            pass

    #开始嗅探
    def start_sniff(self):
        sniff_thread = threading.Thread(target=sniffer, args=(IFACE, self.handle_packets))
        sniff_thread.start()

    #停止嗅探
    def stop_sniff(self):
        global STOP
        STOP = False

    #重新开始
    def restart_sniff(self):
        self.packet_table.clearSpans()

    #过滤数据包
    def filter_pcap(self):
        global FILTER
        filterUI = FilterUI(parent=self)
        if filterUI.exec_():
            FILTER = str(filterUI.get_value())

    #帮助
    def help_me(self):
        QtGui.QMessageBox.information(self, u"帮助", self.tr("先配置要嗅探的网卡，然后启动嗅探器!"))

    #关于
    def about_me(self):
        QtGui.QMessageBox.information(self, u"关于", self.tr("本程序由软件工程11202班董进编写!"))


#选择网卡对话框
class IfaceUI(QtGui.QDialog):
    def __init__(self, parent=None):
        QtGui.QDialog.__init__(self, parent)
        self.resize(500, 200)
        self.setWindowTitle(u'网络适配器选择')
        screen = QtGui.QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)
        self.initUI()
        self.show()

    def initUI(self):
        device_data = get_iface_name()
        iface_num = len(device_data)
        iface_keys = device_data.keys()
        #网卡列表
        self.radio_lists = []
        self.gridlayout = QtGui.QGridLayout()
        self.label_name = QtGui.QLabel(u'接口名')
        self.label_ip = QtGui.QLabel(u'IP地址')
        self.label_receive = QtGui.QLabel(u'接受流量')
        self.label_send = QtGui.QLabel(u'发送流量')
        self.gridlayout.addWidget(self.label_name, 1, 1)
        self.gridlayout.addWidget(self.label_ip, 1, 2)
        self.gridlayout.addWidget(self.label_receive, 1, 3)
        self.gridlayout.addWidget(self.label_send, 1, 4)
        self.setLayout(self.gridlayout)
        for i in range(iface_num):
            iface_name = iface_keys[i]
            self.iface_radio = QtGui.QRadioButton(iface_name)
            if iface_name == 'eth0':
                self.iface_radio.setChecked(True)
            self.gridlayout.addWidget(self.iface_radio, i+2, 1)
            self.radio_lists.append(self.iface_radio)
            self.ip_label = QtGui.QLabel(get_ip_address(iface_name))
            self.gridlayout.addWidget(self.ip_label, i+2, 2)
            data = device_data[iface_name].split(';')
            self.receive_label = QtGui.QLabel(data[0])
            self.send_label = QtGui.QLabel(data[1])
            self.gridlayout.addWidget(self.receive_label, i+2, 3)
            self.gridlayout.addWidget(self.send_label, i+2, 4)
            self.setLayout(self.gridlayout)
        #添加按钮
        self.start_but = QtGui.QPushButton(u'确定', self)
        self.start_but.clicked.connect(self.exit_me)
        self.start_but.setCheckable(False)
        self.gridlayout.addWidget(self.start_but, iface_num + 2, 2)
        self.cancel_but = QtGui.QPushButton(u'取消', self)
        self.connect(self.cancel_but, QtCore.SIGNAL('clicked()'), QtCore.SLOT('close()'))
        self.cancel_but.setCheckable(False)
        self.gridlayout.addWidget(self.cancel_but, iface_num + 2, 3)

    def exit_me(self):
        global IFACE
        for radio in self.radio_lists:
            if radio.isChecked():
                IFACE = radio.text()
        self.setVisible(False)

#显示数据包列表
class Packet_TableView(QtGui.QTableView):
    def __init__(self, parent=None):
        QtGui.QTableView.__init__(self, parent)
        self.model = QtGui.QStandardItemModel(parent=self)
        self.model.setHorizontalHeaderLabels(['Source', 'Destination', 'Protoco', 'Info'])
        self.setModel(self.model)
        self.setColumnWidth(0, 120)
        self.setColumnWidth(1, 120)
        self.setColumnWidth(2, 100)
        self.setColumnWidth(3, 350)
        self.setAlternatingRowColors(True)
        self.setAutoScroll(True)
        self.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows) #整行选中
        self.setEditTriggers(QtGui.QTableView.NoEditTriggers) #不可编辑
        self.setSelectionMode(QtGui.QTableView.SingleSelection) #选择单行
        self.show()

    def mouseDoubleClickEvent(self, QMouseEvent):
        global SELECT_ROW, SELECT_INFO, SHOW2STR, HEXSTR
        QtGui.QTableView.mouseDoubleClickEvent(self, QMouseEvent)
        pos = QMouseEvent.pos()
        item = self.indexAt(pos)
        if item:
            SELECT_ROW = int(item.row())
            SELECT_INFO = PACKETS[SELECT_ROW]
            #输出重定向数据
            show2_temp_name = tempfile.NamedTemporaryFile(prefix='show2_', dir='/tmp')
            old = sys.stdout
            show2_file = open(show2_temp_name.name, 'w')
            sys.stdout = show2_file
            SELECT_INFO.show2()
            sys.stdout = old
            show2_file.close()
            hex_temp_name = tempfile.NamedTemporaryFile(prefix='hex_', dir='/tmp')
            hex_file = open(hex_temp_name.name, 'w')
            sys.stdout = hex_file
            hexdump(SELECT_INFO)
            sys.stdout = old
            hex_file.close()
            #读取数据
            with open(show2_temp_name.name, 'r') as show2f:
                SHOW2STR = show2f.read()
            with open(hex_temp_name.name, 'r') as hexf:
                HEXSTR = hexf.read()
            print('--------------------------------------')
            print(SHOW2STR)
            print(HEXSTR)
            print('--------------------------------------')


    #添加行
    def row_append(self, src, dst, proto, info):
        self.model.appendRow((QtGui.QStandardItem(src),
                              QtGui.QStandardItem(dst),
                              QtGui.QStandardItem(proto),
                              QtGui.QStandardItem(info)))

class ShowInfoUI(QtGui.QDialog):
    def __init__(self, parent=None):
        QtGui.QDialog.__init__(self, parent)
        self.resize(500, 600)
        self.setWindowTitle(u'数据包详细信息')
        screen = QtGui.QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)
        self.initUI()
        self.show()

    def initUI(self):
        self.text_show2 = QtGui.QTextEdit()
        self.text_show2.setText(SHOW2STR)
        self.text_show2.setReadOnly(True)
        self.text_hex = QtGui.QTextEdit()
        self.text_hex.setText(HEXSTR)
        self.text_hex.setReadOnly(True)
        self.save_but = QtGui.QPushButton(u'保存为PDF', self)
        self.save_but.setCheckable(False)
        self.save_but.clicked.connect(self.save_pdf)
        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(self.text_show2)
        vbox.addWidget(self.text_hex)
        vbox.addWidget(self.save_but)
        self.setLayout(vbox)
        """
        self.splitter = QtGui.QSplitter(self)
        self.splitter.addWidget(self.text_show2)
        self.splitter.addWidget(self.text_hex)
        self.splitter.setOrientation(QtCore.Qt.Vertical)
        """

    def save_pdf(self):
        save_name = QtGui.QFileDialog.getSaveFileName(self, self.tr("Save PDF"), '.', self.tr("Packets Files(*.pdf)"))
        if save_name:
            name = str(save_name + '.pdf')
            SELECT_INFO.pdfdump(name)
            QtGui.QMessageBox.information(self, u"保存成功", self.tr("PDF保存成功!"))

class FilterUI(QtGui.QDialog):
    def __init__(self, parent=None):
        QtGui.QDialog.__init__(self, parent)
        self.resize(300, 100)
        self.setWindowTitle(u'过滤器')
        screen = QtGui.QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)
        self.initUI()
        self.show()

    def initUI(self):
        grid = QtGui.QGridLayout()

        grid.addWidget(QtGui.QLabel(u'过滤规则:', parent=self), 0, 0, 1, 1)
        self.filter = QtGui.QLineEdit(parent=self)
        grid.addWidget(self.filter, 0, 1, 1, 1)
        # 创建ButtonBox，用户确定和取消
        buttonBox = QtGui.QDialogButtonBox(parent=self)
        buttonBox.setOrientation(QtCore.Qt.Horizontal) # 设置为水平方向
        buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok) # 确定和取消两个按钮
        # 连接信号和槽
        buttonBox.accepted.connect(self.accept) # 确定
        buttonBox.rejected.connect(self.reject) # 取消
        # 垂直布局，布局表格及按钮
        layout = QtGui.QVBoxLayout()
        # 加入前面创建的表格布局
        layout.addLayout(grid)
        # 放一个间隔对象美化布局
        spacerItem = QtGui.QSpacerItem(20, 48, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        layout.addItem(spacerItem)
        # ButtonBox
        layout.addWidget(buttonBox)
        self.setLayout(layout)

    def get_value(self):
        return self.filter.text()

#获取网卡名称
def get_iface_name():
    with open('/proc/net/dev') as f:
        net_dump = f.readlines()
    device_data = {}
    for line in net_dump[2:]:
        line = line.split(':')
        device_data[line[0].strip()] = format(float(line[1].split()[0])/(1024.0*1024.0), '0.2f') + " MB;" + format(float(line[1].split()[8])/(1024.0*1024.0), '0.2f') + " MB"
    return device_data

#获取网卡IP地址
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])

#嗅探
def sniffer(IFACE, handle):
    sniff(iface=str(IFACE), prn=handle)

def main():
    app = QtGui.QApplication(sys.argv)
    sniffer = SnifferUI()
    sniffer.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
