from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from scapy.all import srp
import socket

def is_printer_by_ports(ip_address):
    printer_ports = [161, 16, 9100, 631, 515]  # 添加打印机常用端口
    for port in printer_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            sock.close()
            return True
        sock.close()
    return False

def make_sure_port(ip):
    # 扫描端口范围
    start_port = 1
    end_port = 9200

    # 遍历指定范围的端口
    for port in range(start_port, end_port + 1):
        try:
            # 创建TCP套接字
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # 设置连接超时时间（单位：秒）
            sock.settimeout(1)

            # 尝试连接目标IP和端口
            result = sock.connect_ex((ip, port))

            # 如果连接成功，返回值为0
            if result == 0:
                print(f"端口 {port} 开放")

            # 关闭套接字
            sock.close()

        except socket.error:
            pass

# 定义本地MAC地址和目标IP地址
local_mac = get_if_hwaddr("en0")  # 本地MAC地址
target_ip = "10.0.0.1/24"  # 目标IP地址

# 构造ARP请求数据包
arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip)

# 发送ARP请求并接收响应
arp_response = srp(arp_request, timeout=2, verbose=False)[0]

# # 处理ARP响应数据包
if arp_response:
    for packet in arp_response:
        if packet[1].haslayer(ARP):
            source_ip = packet[1][ARP].psrc
            source_mac = packet[1][ARP].hwsrc
            if is_printer_by_ports(source_ip) == True:
                is_printer = "Y"
            else:
                is_printer = "N"

            try:
                # 查询设备的主机名
                source_host = socket.gethostbyaddr(source_ip)[0]
            except socket.herror:
                source_host = "Unknown"  # 如果无法解析主机名，则将其设置为"Unknown"
            print("ARP Response: IP = {}, MAC = {}, Printer = {}, Host = {}".format(source_ip, source_mac, is_printer, source_host))
            # make_sure_port(source_ip)
else:
    print("No ARP response received.")