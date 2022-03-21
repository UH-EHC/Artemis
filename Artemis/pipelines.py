# -*- coding: utf-8 -*-
# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html
import logging
import nmap
import Artemis.settings as settings

logger = logging.getLogger('Artemis_log')

class ArtemisPipeline(object):
    
    def scanner(self, target, option=0):
        nmScan = nmap.PortScanner()
        # default
        params = '-v -sS' 
        ports = '{}-{}'.format(settings.PS, settings.PE)
        if option == 1:
            params = '-v -sT' 
        # nm.scan('127.0.0.1', '22-443')
        # nm.scaninfo()
        # nm['127.0.0.1'].has_tcp(22)

        # running nmap
        try:
            result = nmScan.scan(target, ports, arguments=params, sudo=True)
        except:
            logger.debug('nmap scanner error: unknown')
            return None
        # need to decide what infomation we need
        return result

    # process and analyze input domain
    def process_item(self, domain):
        """
        :param domain: domain (ip)
        :return: N/A
        """
        # logger.debug(), logger.warning(), logger.info()
        # TODO STEP 2: using port scanner for initial information
        # Service enamuration
        print("================= DOMAIN: {} =================".format(domain))
        print("================= PORT SCANNER =================")
        scan_result = self.scanner(domain, option=settings.NMAP_option)
        for key in scan_result:
            if type(scan_result[key]) == dict:
                for key_2 in scan_result[key]:
                    print(scan_result[key][key_2])
            else:
                print(scan_result[key])

        # nmScan = nmap.PortScanner()
        # port_range = '-'.join([str(settings.PS), str(settings.PE)])
        # nmap_result = nmScan.scan(domain, port_range)
        # # nmap scan info
        # command_line = nmap_result['nmap']['command_line']
        # scaninfo = nmap_result['nmap']['scaninfo']
        # scanstats = nmap_result['nmap']['scanstats']
        # ip_addr = list(nmap_result['scan'].keys())[0]
        # hostname = nmap_result['scan'][ip_addr]['hostnames']
        # addresses = nmap_result['scan'][ip_addr]['addresses']
        # vendor = nmap_result['scan'][ip_addr]['vendor']
        # status = nmap_result['scan'][ip_addr]['status']
        # tcp = nmap_result['scan'][ip_addr]['tcp']

        # print('command_line used: {}'.format(command_line))
        # print('scaninfo: {}'.format(scaninfo))
        # print('scanstats: {}'.format(scanstats))
        # print('ip_addr: {}'.format(ip_addr))
        # print('hostname: {}'.format(hostname))
        # print('addresses: {}'.format(addresses))
        # print('vendor: {}'.format(vendor))
        # print('status: {}'.format(status))
        # print('tcp: {}'.format(tcp))

        # TODO STEP 3: analysis
        # Vulnerability Analysis
        # E.g: Port numbers/range , Port status, Service enamuration, Vulnerabiliy search
        print("================= VULNERABILITY ANALYSIS =================")
        # analysis 1: vulnerable service search

        # analysis 2: sqlmap

        # analysis 3: sensitive public files check

        # etc.

        # TODO STEP 4: report
        print("================= REPORT =================")