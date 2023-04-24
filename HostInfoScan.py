#!/usr/bin/env python
# -*- coding: utf-8 -*-

from base64 import b64encode
from argparse import ArgumentParser, FileType
from queue import Queue
from threading import Thread
from threading import RLock
import sys
import socket
import ipaddress
import logging
import binascii, time

TIME_OUT = 3
RESULT_LIST1 = []
RESULT_LIST2 = []
length = 0


def get_ip_list(ip_str) -> list:
    ip_list = []
    if '.txt' in ip_str:   
        with open(ip_str, 'r') as f:
            for ip in f.readlines():
                ip_list.extend(get_ip_list(ip.strip('\n')))
    else:
        if '-' in ip_str:
            for i in range(int(ip_str.split('-')[0].split('.')[3]), int(ip_str.split('-')[1]) + 1):
                ip_list.append(ip_str.split('.')[0] + '.' + ip_str.split('.')[1] + '.' + ip_str.split('.')[2] + '.' + str(i))
        elif '/' in ip_str:
            try:
                for ip in ipaddress.IPv4Network(ip_str).hosts():
                    ip_list.append(str(ip))
            except ValueError:
                ip_str = ip_str.split('.')[0] + '.' + ip_str.split('.')[1] +'.' + ip_str.split('.')[2] + '.' + '0' + '/24'
                for ip in ipaddress.IPv4Network(ip_str).hosts():
                    ip_list.append(str(ip))
        else:
            ip_list.append(ip_str.strip())
    return ip_list


def attribute_name(Target_Info_bytes):
    global length
    att_name_length = int.from_bytes(Target_Info_bytes[length + 2:length + 4], byteorder='little')
    att_name = Target_Info_bytes[length + 4:length + 4 + att_name_length].replace(b"\x00", b"").decode(
        encoding="unicode_escape")
    length = length + 4 + att_name_length
    return att_name


def send_packet(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIME_OUT)
        sock.connect((ip, 135))
        buffer_v1 = b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa\x03\x00\x00\x00\x33\x05\x71\x71\xba\xbe\x37\x49\x83\x19\xb5\xdb\xef\x9c\xcc\x36\x01\x00\x00\x00"
        sock.send(buffer_v1)
        packet1 = sock.recv(1024)
        digit = "x86"
        if b"\x33\x05\x71\x71\xBA\xBE\x37\x49\x83\x19\xB5\xDB\xEF\x9C\xCC\x36" in packet1:
            digit = "x64"
        return digit
    except Exception as e:
        # print(e)
        return -1
    finally:
        sock.close()


def get_osinfo(ip):
    global length
    lock = RLock()

    osinfo = {
        "NetBIOS_domain_name": "",
        "NetBIOS_computer_name": "",
        "DNS_domain_name": "",
        "DNS_computer_name": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIME_OUT)
        sock.connect((ip, 135))
        buffer_v2 = b"\x05\x00\x0b\x03\x10\x00\x00\x00\x78\x00\x28\x00\x03\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x01\x00\xa0\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00\x0a\x02\x00\x00\x00\x00\x00\x00\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x01\xb1\x1d\x00\x00\x00\x0f"
        sock.send(buffer_v2)
        packet2 = sock.recv(4096)
        #print(packet2)
        digit = send_packet(ip)
        OS_Version_bytes = packet2[int('0xa0', 16) - 54 + 10:int('0xa0', 16) - 54 + 18]
        Major_Version = int.from_bytes(OS_Version_bytes[0:1], byteorder='little')
        Minor_Version = int.from_bytes(OS_Version_bytes[1:2], byteorder='little')
        Build_Number = int.from_bytes(OS_Version_bytes[2:4], byteorder='little')
        NTLM_Current_Reversion = int.from_bytes(OS_Version_bytes[7:8], byteorder='little')
        OS_Verison = "Windows Version {0}.{1} Build {2} {3}".format(Major_Version, Minor_Version, Build_Number, digit)

        Target_Info_Length_bytes = packet2[int('0xa0', 16) - 54 + 2:int('0xa0', 16) - 54 + 4]
        Target_Info_Length = int.from_bytes(Target_Info_Length_bytes, byteorder='little')
        Target_Info_bytes = packet2[-Target_Info_Length:-4]  # 最后四个0x00000000
        lock.acquire()  # 上锁
        print("[*] " + ip + ' OS Info :')
        print("\t[->]", "OS_Verison :", OS_Verison)
        #print(Target_Info_bytes)
        for k in osinfo.keys():
            osinfo[k] = attribute_name(Target_Info_bytes)
            print("\t[->]", k, ":", osinfo[k])
        lock.release()  # 开锁
        length = 0
        osinfo["OS_Verison"] = OS_Verison
        result = {ip: osinfo}
        return result
    except Exception as e:
        return -1
    finally:
        sock.close()

def get_addres(ip):
    lock = RLock()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIME_OUT)
        sock.connect((ip,135))
        buffer_v1 = b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"
        buffer_v2 = b"\x05\x00\x00\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00"
        sock.send(buffer_v1)
        packet = sock.recv(1024)
        sock.send(buffer_v2)
        packet = sock.recv(4096)
        #print(packet)
        packet_v2 = packet[42:]
        packet_v2_end = packet_v2.find(b"\x09\x00\xff\xff\x00\x00")
        packet_v2 = packet_v2[:packet_v2_end]
        hostname_list = packet_v2.split(b"\x00\x00")
        #print(hostname_list)
        result = {ip:[]}
        lock.acquire()  # 上锁
        print("[*] " + ip + ' Network Info :')
        for h in hostname_list:
            h = h.replace(b'\x07\x00',b'')
            h = h.replace(b'\x00',b'')
            if h == '':
                continue
            if h.decode() != '':
                print("\t[->]" + h.decode())
                result[ip].append(h)
        lock.release()  # 开锁
        #print(result)
        return result
    except Exception as e:
        return -1
    finally:
        sock.close()

def worker(q,a):
    while True:
        try:
            data = q.get()
            if a == 1:
                result1 = get_osinfo(data)
                if result1 != -1 :
                    RESULT_LIST1.append(result1)
            elif a == 2:
                result2 = get_addres(data)
                if result2 != -1:
                    RESULT_LIST2.append(result2)
            else:
                result1 = get_osinfo(data)
                result2 = get_addres(data)
                if result1 != -1 and result2 != -1:
                    RESULT_LIST1.append(result1)
                    RESULT_LIST2.append(result2)
        except Exception as e:
            sys.stderr.write(str(e))
        finally:
            q.task_done()


def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--ip', help=u'IP Address,expample:192.168.0.1, 192.168.0.1-100, 192.168.0.1/24, ip.txt', required=True,type=str)
    parser.add_argument('-t', '--threads', help=u'threads, default 20', default=20, type=int)
    parser.add_argument('-a', '--attack', help=u'choose attack:   0:all 1:OSInfo 2:NetWorkInfo, defualt 0', default=0, type=int)
    parser.add_argument('-o', '--output', help=u'Output result, default: log.txt', default='log.txt', type=FileType('a+'))

    args = parser.parse_args()
    if args.ip is None:
        print("Some Wrong.")
    q = Queue(args.threads)

    for _ in range(args.threads):
        t = Thread(target=worker, args=(q,args.attack))
        t.daemon = True
        t.start()

    ip_list = get_ip_list(args.ip)

    for i in ip_list:
        q.put(i)
    q.join()

    for osinfo_dict in RESULT_LIST1:
        for ip in osinfo_dict.keys():
            args.output.write("[*] " + ip + "\n")
            for k, v in osinfo_dict[ip].items():
                args.output.write("\t[->] " + k + ":" + v + "\n")
        # print(osinfo_dict)
    for host in RESULT_LIST2:
        for ip in host.keys():
            args.output.write("[*] " + ip + "\n")
            for other_ip in host[ip]:
                if other_ip.decode() != '':
                    args.output.write("\t[->] " + other_ip.decode() + "\n")

if __name__ == '__main__':
    main()
