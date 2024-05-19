import socket
import threading
from ipaddress import ip_network

print_lock = threading.Lock()

#common protocols on ports
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    587: "SMTP",
    993: "IMAP",
    995: "POP3"
}

def get_version(sock, port):
    try:
        if port == 80:  # HTTP
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024).decode().strip()
            return response.split("\r\n")[0]
        elif port == 443:  # HTTPS
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024).decode().strip()
            return response.split("\r\n")[0]
        elif port == 21:  # FTP
            response = sock.recv(1024).decode().strip()
            return response
        elif port == 22:  # SSH
            response = sock.recv(1024).decode().strip()
            return response
        #I can add future version numbers and protocol numbers later to make more accurate
    except Exception as e:
        return f"unknown (error: {e})"
    return "unknown"

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                banner = sock.recv(1024).decode().strip()
                if banner:
                    with print_lock:
                        print(f"Port {port} is open on {ip} - service: {banner}")
                else:
                    service = common_ports.get(port, "unknown")
                    version = get_version(sock, port)
                    with print_lock:
                        print(f"Port {port} is open on {ip} - service: {service} - version: {version}")
            except socket.timeout:
                with print_lock:
                    print(f"Port {port} is open on {ip} - service: {common_ports.get(port, 'unknown')} (no banner)")
            finally:
                sock.close()
        else:
            with print_lock:
                print(f"Port {port} is closed on {ip}")
    
    except socket.error as err:
        with print_lock:
            print(f"Socket error on {ip}:{port} - {err}")

#Used for threading
def scan_ports(ip, ports):
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(ip, port))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()

def scan_network(network, ports):
    network_hosts = list(ip_network(network).hosts())
    for host in network_hosts:
        ip = str(host)
        print(f"Scanning {ip}")
        scan_ports(ip, ports)

if __name__ == "__main__":
    network = '8.8.8.8'  #need make user input later
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 993, 995] #temporary common inpurts, will have user inputs
    scan_network(network, ports)
