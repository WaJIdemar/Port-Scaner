import argparse
import socket
from queue import Queue
from threading import Thread

N_THREADS = 200
q = Queue()
TIMEOUT = 1

ports_info = {}


def tcp_port_scan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(TIMEOUT)
        s.connect((host_ip, port))
        ports_info[port] = None
        s.sendall(b"GET / HTTP/1.1\nhost: " + bytes(host, "utf-8") + b"\n\n")
        data = s.recv(1024)
        data_str = data.decode("utf-8")
        if "+OK" in data_str:
            ports_info[port] = "POP3"
        elif "IMAP" in data_str:
            ports_info[port] = "IMAP"
        elif "220" in data_str:
            ports_info[port] = "SMTP"
        if "HTTP" in data_str and "HTTPS" not in data_str:
            ports_info[port] = "HTTP"
    except:
        pass
    finally:
        s.close()


def udp_port_scan(port):
   pass


def scan_tcp_thread():
    global q
    while True:
        worker = q.get()
        tcp_port_scan(worker)
        q.task_done()


def scan_udp_thread():
    global q
    while True:
        worker = q.get()
        udp_port_scan(worker)
        q.task_done()


def main(host, ports):
    global q
    for i in range(N_THREADS):
        if tcp:
            t = Thread(target=scan_tcp_thread)
            t.daemon = True
            t.start()
        elif udp:
            t = Thread(target=scan_udp_thread)
            t.daemon = True
            t.start()

    for worker in ports:
        q.put(worker)

    q.join()


def print_info():
    for port, info in ports_info.items():
        if tcp:
            if info:
                line = "TCP " + str(port) + " " + str(info)
            else:
                line = "TCP " + str(port)
            print(line)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple port scanner")
    parser.add_argument("host", help="Host to scan.")
    parser.add_argument("-t", dest="tcp", action="store_true", default=False)
    parser.add_argument("-u", dest="udp", action="store_true", default=False)
    parser.add_argument("--ports", "-p", dest="port_range", default=[1, 65535],
                        nargs=2,
                        help="Port range to scan, default is 1-65535 (all ports)")
    args = parser.parse_args()
    tcp = args.tcp
    udp = args.udp
    if udp:
        print("Not implemented yet")
        quit()
    host, port_range = args.host, args.port_range
    host_ip = socket.gethostbyname(host)
    start_port, end_port = port_range[0], port_range[1]
    start_port, end_port = int(start_port), int(end_port)
    ports = [p for p in range(start_port, end_port + 1)]
    main(host, ports)
    print_info()
