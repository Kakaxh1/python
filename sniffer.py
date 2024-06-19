from colorama import init,Fore
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest,TCP
import argparse



init()

red = Fore.RED
blue = Fore.BLUE
yellow = Fore.YELLOW
reset = Fore.RESET
#iface1 = 'eth0'
argparse = argparse.ArgumentParser(description="this is tool for sniffing.",usage="sniff")
argparse.add_argument("-i","--INTERFACE",help="interface for sniffing")
args = argparse.parse_args()
iface1=args.INTERFACE


def sniff_packet(iface):
    if iface:
        print ("interface is "+iface)
        sniff(prn=process_packet, iface=iface, store=False)
    else:
        print("default interface")
        sniff(prn=process_packet, store=False)

def process_packet(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        scr_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"{blue}{src_ip} is using port {scr_port} to connect to {dst_ip} at {dst_port}{reset}")
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()
        http_packet = packet[HTTPRequest].show()
        print(f"{yellow} {src_ip} is making a HTTP request to {url} with method {method} {reset}")
        print(f"{http_packet}")
        if packet.haslayer(Raw):
            print(f"[+]{red}{packet.getlayer(Raw).load.decode()} {reset}")



sniff_packet(iface1)

