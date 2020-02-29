import socket
import time
import sys
import os
import threading
from threading import *
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP
from collections import defaultdict

TAB_1 = '-'
TAB_2 = '   - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '
syn_counter=0
ip_list = []
storesyn=[]
dic = defaultdict(int)

#this function just stores all the TCP-segments involved in TCP handshake and check for the half-open connections at same time.
def storeip(srcIP,dstIP,pktSyn,pktack,srcport,dstport):
    temp_list=[srcIP,dstIP,pktSyn,pktack]
    ip_list.append(temp_list)
    k = srcIP+dstIP
    if pktSyn == 1 and pktack == 0:
        dic[srcIP+dstIP] += 0.5
    elif pktSyn == 1 and pktack == 1:
        dic[dstIP+srcIP] += 0.5
        if dic[dstIP+srcIP] >= 25:
            print("Server is under attack")
            os._exit(1)
    elif pktSyn == 0 and pktack == 1:
        dic[srcIP+dstIP] -= 1    
       
#This function will just print the network fields of all IP packets 
def printpkt(src,destination,protocol,flagsyn,flagack,srcport,destport):
    print(src,TAB_1,destination,TAB_1,protocol,TAB_2,srcport,TAB_2,destport)

#This function just stores the IP address which initates TCP-handshakes
def storesynip(newip,dsttip):
    temp_list=[newip,dsttip]
    global syn_counter
    syn_counter +=1
    if len(storesyn)>0:
        if newip in storesyn:
            pass
        else:
            storesyn.append(temp_list)
            
    else:
        storesyn.append(temp_list)
        
    dic[dsttip+newip]

#this function will continuosly check the value of syn_counter
def checknow ():
    time.sleep(4)
    global syn_counter
    if syn_counter >= 10:
        print("SYN per second threshold Reached, Server might be under attack",syn_counter)
        os._exit(0)
    else:
        pass

#main function
def main():
    print("#################Capturing Packets############")
    print(TAB_1 +"Source IP"+TAB_1+"Destination IP"+TAB_1+"Protocol"+TAB_1+"Source Port"+TAB_1+"Destination Port")
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)
# Extracting the IPv4 Packet from ethernet frame
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            # This is the part which extract TCP packet from IPv4 Packet
            if ipv4.proto == 6:
                tcp = TCP(ipv4.data)
# Multithreading that receives SYN connection and checks for SYN flood attack Simultaneously.
                threading.Thread(target= printpkt,args=(ipv4.src,ipv4.target,ipv4.proto,tcp.flag_syn,tcp.flag_ack,tcp.src_port,tcp.dest_port,)).start()
                if tcp.flag_syn == 1 and ipv4.target == "192.168.2.34":
                    t1 = threading.Thread(target= storesynip,daemon=True, args=(ipv4.src,ipv4.target,)).start()  
                threading.Thread(target= storeip,args=(ipv4.src,ipv4.target,tcp.flag_syn,tcp.flag_ack,tcp.src_port,tcp.dest_port,)).start()
                threading.Thread(target= checknow).start()
    pcap.close()
main()
