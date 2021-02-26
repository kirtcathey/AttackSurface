# AttackSurface
import nmap


def scan_hosts():
    arg = '-sV -iL /home/kali/host_ips.txt -oG scan_output.txt'
    nm = nmap.PortScanner()
    data = nm.scan(arguments=arg)

    # with open('~/host_ips.txt') as f:
    #     lines = [line.rstrip() for line in f]
    #     result = nm.nmap_version_detection(lines)
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)

    lport = nm[host][proto].keys()
    lport.sort()
    for port in lport:
        print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
        print('----------------------------------------------------')


if __name__ == '__main__':
    #   Call function to perform initial scan.
    scan_hosts()
