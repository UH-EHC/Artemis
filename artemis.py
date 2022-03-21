#!/bin/python
import sys, os, argparse, hashlib, time, nmap
from responses import target

def main():
    parser = argparse.ArgumentParser(description='three-pronged hash cracking tool')

    parser.add_argument('-s', dest='_scantype',type=str, help='type of scan tp run (service/os/vuln/safe)')
    parser.add_argument('-t', dest='_target', type=str, help ='target IP')
    parser.add_argument('-p', dest='_portrange',type=str, help='port range')
    
    args = parser.parse_args()

    scantype = args._scantype
    target = args._target
    port_range = args._portrange
    
    ps = nmap.PortScanner()
    ps.scan(target, port_range)
    
    
    print(ps.scaninfo())

    

if __name__ == "__main__":
    main()  