import queue
import time

from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
import argparse
import sys

print("*" * 50)
print("Python simple port scanner")
print("*" * 50)

result = "port\tSTATUS\n"
# arg parsing
parser = argparse.ArgumentParser("Port scanner using Scapy")
parser.add_argument("-d", "--target", help="Specify target IP", required=True)
parser.add_argument("-p", "--ports", type=int, nargs="+", help="Specify starting ports (21 23 80 ...)")
parser.add_argument("-v", "--verbose", help="Specify verbose")
parser.add_argument("-s", "--scantype", help="Scan type, syn/udp/xmas", required=True)
parser.add_argument("-t", "--Threading", help="Specify number thread")
args = parser.parse_args()

target = args.target

try:
    target = socket.gethostbyname(target)
except:
    print("[-] Host resolution failed")
    exit()

scantype = args.scantype.lower()
verbose = args.verbose
port = args.ports
start_port = port[0]
end_port = port[1]

try:
    thread_no = int(args.Threading)
except:
    pass
    thread_no=''
print("Target\t\t{}\nStarting port\t{}\nEnd port\t{}\nscan type\t{}".format(target, start_port, end_port,scantype))
end_port += 1
def print_ports(port, state):
    if not verbose:
        print("{} | {}".format(port, state))


def print_output():
    global result
    print(result)


# syn scan
def syn_scan(t_no):
    global result
    sport = RandShort()
    while not q.empty():
        port = q.get()
        pkt = sr1(IP(dst=target) / TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 20:
                    print_ports(port, "Closed")
                elif pkt[TCP].flags == 18:
                    print_ports(port, "Open")
                    result += f"{port}\tOpen \n"
                else:
                    print_ports(port, "TCP packet resp / filtered")
                    result += f"{port}\tTCP packet resp / filtered\n"
            elif pkt.haslayer(ICMP):
                print_ports(port, "ICMP resp / filtered")
                result += f"{port}\tICMP resp / filtered\n"
            else:
                print_ports(port, "Unknown resp")
                print(pkt.summary())
        else:
            print_ports(port, "Unanswered")
    q.task_done()

#udp scan
def udp_scan(target, ports):
    global result
    print("udp scan on, {} with ports {}".format(target, ports))
    while not q.empty():
        port = q.get()
        pkt = sr1(IP(dst=target) / UDP(sport=port, dport=port), timeout=2, verbose=0)
        if pkt == None:
            print_ports(port, "Open / filtered")
            result += f"{port}\tOpen / filtered\n"
        else:
            if pkt.haslayer(ICMP):
                print_ports(port, "Closed")
            elif pkt.haslayer(UDP):
                print_ports(port, "Open / filtered")
                result += f"{port}\tOpen / filtered\n"
            else:
                print_ports(port, "Unknown")
                print(pkt.summary())
    q.task_done()


# xmas scan
def xmas_scan(target, ports):
    global result
    print("Xmas scan on, {} with ports {}".format(target, ports))
    sport = RandShort()
    while not q.empty():
        port = q.get()
        pkt = sr1(IP(dst=target) / TCP(sport=sport, dport=port, flags="FPU"), timeout=1, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 20:
                    print_ports(port, "Closed")
                else:
                    print_ports(port, "TCP flag {}".format(pkt[TCP].flag))
            elif pkt.haslayer(ICMP):
                print_ports(port, "ICMP resp / filtered")
                result += f"{port}\tICMP resp / filtered\n"
            else:
                print_ports(port, "Unknown resp")
                result += f"{port}, Unknown resp\n"
                print(pkt.summary())
        else:
            print_ports(port, "Open / filtered")
            result += f"{port}\tOpen / filtered\n"
    q.task_done()


q = queue.Queue()
for j in range(start_port, end_port):
    q.put(j)

if args.ports:
    ports = range(start_port, end_port)
else:
    # default port range
    ports = range(1, 1024)


if thread_no:
    if scantype == "syn" or scantype == "s":
        for i in range(thread_no + 1):
            t = threading.Thread(target=syn_scan, args=(i,))
            t.start()

    elif scantype == "udp" or scantype == "u":
        for i in range(thread_no):
            t = threading.Thread(target=udp_scan, args=(i,))
            t.start()
    elif scantype == "xmas" or scantype == "x":

        for i in range(thread_no):
            t = threading.Thread(target=xmas_scan, args=(i,))
            t.start()
    else:
        print("Scan type not supported")
else:
    if scantype == "syn" or scantype == "s":
        syn_scan(1)
    elif scantype == "udp" or scantype == "u":
        udp_scan(1)
    elif scantype == "xmas" or scantype == "x":
        xmas_scan(1)

with open(target + '.txt', 'w') as file:
    time.sleep(1)
    file.write(result)
