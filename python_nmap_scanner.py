import nmap
import ipaddress

while True: # valid user input.
    target = input("Please enter IP address or range of IP addresses to scan: ")
    try:
        network = ipaddress.ip_address(target)
        break
    except ValueError:
        try:
            network = ipaddress.ip_network(target, strict=False)
            break
        except ValueError:
            print("Invalid IP address or network entered")
print("Scanning", network, "in progress...")

# Nmap library to scan specified IP address or range of IP addresses the user enterd.
scanner = nmap.PortScanner()
try:
    scanner.scan(target)

except nmap.PortScannerError as e:
    print("Error: ", e)

# Check if the hosts were successfully scanned.
if scanner.scanstats()['uphosts'] == '0':
    print("The IP address or range of IP addresses is unreachable for scanning")
    exit()

# Getting info on open ports, services, and operating systems.
results = []
for host in scanner.all_hosts():
    open_ports = []
    for proto in scanner[host].all_protocols():
        port_info = scanner[host][proto]
        for port in port_info:
            if port_info[port]['state'] == 'open':
                open_ports.append(port)
    services = [port_info[port]['name'] for port in open_ports]
    os_info = scanner[host]['osmatch'][0]['name'] if 'osmatch' in scanner[host] else 'Unknown'
    results.append({'host': host, 'open_ports': open_ports, 'services': services, 'os_info': os_info})

# Print the scan information.
print(f"\nScan result:\nHosts up: {scanner.scanstats()['uphosts']}\nHosts down: {scanner.scanstats()['downhosts']}\nTotal hosts: {scanner.scanstats()['totalhosts']}\nScan time: {scanner.scanstats()['elapsed']}\nInformation:\n")

for result in results:
    print(f"Host: {result['host']}\nOpen ports: {result['open_ports']}\nServices: {result['services']}\nOperating system: {result['os_info']}\n")