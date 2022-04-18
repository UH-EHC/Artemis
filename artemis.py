#!/bin/python
import argparse
import nmap
# import os
# import sys
import textwrap
# import time


def parse_result(nmScan, scantype):
    for host in nmScan.all_hosts():
        host = nmScan[host]
        # osresults = host['osmatch']
        print('----------------------------------------------------')
        print('Host : %s' % host.hostname())
        print('State : %s' % host.state())

        if 'osmatch' in host:
            print('----------')
            if len(host['osmatch']) >= 2:
                print('Multiple OS matches. Results may be innaccurate. nmap requires at least one open and one closed port to detect OS.')
            print("OS Name : %s" % host['osmatch'][0]['name'])
            print("OS CPE : %s" % host['osmatch'][0]['osclass'][0]['cpe'][0])

        for proto in host.all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            lport = host[proto].keys()
            # lport.sort()
            for port in lport:
                print ('port : %s\tstate : %s' % (port, host[proto][port]['state']))

    # key = list(result['scan'].keys())[0]
    # # print(result['scan']['169.46.123.165'].keys())
    # # print(result['scan'][key]['tcp'])
    # tcp_info = result['scan'][key]['tcp']
    # for port_num in tcp_info:
    #     print('{}: {}'.format(port_num, tcp_info[port_num]))
    # print()
   
    pass
    
def main():
    parser = argparse.ArgumentParser(description='Artemis - Port Scanner, Vulnerability Analysis',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''Example: 
    
    artemis.py -t 10.0.0.1 -p 5555 -s service
    '''))

    parser.add_argument('-s', dest='_scantype', metavar='', type=str, help='type of scan to run ( aggressive | quiet | default )', default='default')
    parser.add_argument('-t', dest='_target', metavar='', type=str, help ='target IP (default = 127.0.0.1)', default='127.0.0.1')
    parser.add_argument('-p', dest='_portrange', metavar='', type=str, help='port range (default = 1-500)', default='1-500')
    
    args = parser.parse_args()

    scantype = args._scantype
    target = args._target
    port_range = args._portrange
    
    nmScan = nmap.PortScanner()
    
    if scantype == 'aggressive':
        params = '-O -Pn -sV -sC -v -T5'
    elif scantype == 'quiet':
        params = '-T0 --spoof-mac Netgear'
    elif scantype == 'default':
        params = '-sV -sC'
    else:
        print('Invald scan type. Valid scans: ( aggressive | quiet | default )')

    print(f'Executing {scantype} scan')
    nmScan.scan(target, port_range, arguments=params, sudo=True)
    # result = nmScan.scan(target, port_range, arguments=params, sudo=True)
    # print(result)
    # result = parse_result()
    parse_result(nmScan, scantype)     

    

if __name__ == "__main__":
    main()  
