import socket, sys
import time, queue
import threading
import requests

usage = "python3 scanner.py TARGET START_PORT END_PORT THREADS "

print("*"*50)
print("Python simple port scanner")
print("*"*50)
try:
    target = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    thread_no = int(sys.argv[4])
except:
    print(usage)
    exit()

result = "[+} result:\nport\tSTATE\tService\n"

try:
    target = socket.gethostbyname(target)
except:
    print("[-] Host resolution failed")
    exit()

def get_banner(port,s):
    if (port == 80 ):
        response = requests.get("http://"+target)
        return response.headers['server']
    return s.recv(1024).decode()

def scan_port(t_no):
    global result
    while not q.empty():
        port = q.get()
        print("scanning for port {}".format(port))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            conn = s.connect_ex((target,port))
            if not conn:
                banner = get_banner(port,s)
                banner = ''.join(banner.splitlines())
                result += f"{port}\tOPEN\t{banner}\n"
            s.close()
        except Exception as e:
            print(e)


        q.task_done()
q = queue.Queue()

start_time = time.time()

for j in range(start_port, end_port+1):
    q.put(j)

for i in range(thread_no):
    t = threading.Thread(target=scan_port, args=(i, ))
    t.start()

q.join()

end_time = time.time()

print("Taken time : {}".format(end_time-start_time))
print(result)
