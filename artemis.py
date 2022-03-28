#!/bin/python
import sys, os, argparse, hashlib, time, nmap
from responses import target


def parse_result(result):
    print(result.keys())
    key = list(result['scan'].keys())[0]
    # print(result['scan']['169.46.123.165'].keys())
    # print(result['scan'][key]['tcp'])
    tcp_info = result['scan'][key]['tcp']
    for port_num in tcp_info:
        print('{}: {}'.format(port_num, tcp_info[port_num]))
    # print()

    
    
    
    pass
    
def main():
    parser = argparse.ArgumentParser(description='Port Scanner')

    parser.add_argument('-s', dest='_scantype',type=str, help='type of scan tp run (service/os/vuln/safe)', default='service')
    parser.add_argument('-t', dest='_target', type=str, help ='target IP', default='127.0.0.1')
    parser.add_argument('-p', dest='_portrange',type=str, help='port range', default='1-500')
    
    args = parser.parse_args()

    scantype = args._scantype
    target = args._target
    port_range = args._portrange
    
    nmScan = nmap.PortScanner()
    
    if scantype == 'service':
        params = '-sV -v'
        # ports = '1-500'
        result = nmScan.scan(target, port_range, arguments=params, sudo=True)
        print(result)
        result = parse_result(result)
    elif scantype == 'os':
        pass
        
    # ps = nmap.PortScanner()
    # ps.scan(target, port_range)
    
    
    # print(ps.scaninfo())

    

if __name__ == "__main__":
    main()  