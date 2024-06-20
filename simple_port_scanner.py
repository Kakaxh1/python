import socket, sys
import time

usage ="python3 simple_port_scanner.py TARGET START_PORT END_PORT"

print("*"*50)
print("Python simple port scanner")
print("*"*50)

target = sys.argv[1]
target = socket.gethostbyname(target)
start_port = sys.argv[2]
end_port = sys.argv[3]

if not target or not str(start_port) or not end_port:
  print(usage) 

start_time = time.time()
for port in range(start_port,end_port +1):
  print(""scanning for port {}.." .format(port))
  s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(1)
  conn = s.connent_ex((target,port))
  if not conn:
    print("[+] port {} is open" .format(port))
                      
end_time = time.time()
print("Time taken: {}".format(end_time-start_time))
