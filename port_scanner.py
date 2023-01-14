"""This script is used to port scanning of target machine"""
from pyfiglet import Figlet 
import socket 
import nmap 
import argparse 
import json 
import os 
import uuid
import sys
import time



custom_fig = Figlet(font='slant')
print(custom_fig.renderText('PORT SCANNER PYTHON!!!'))


parser = argparse.ArgumentParser(description="""
This is the nmap port scanning through python....
this script will help you more flexibility of port scanning 
and it will return json file contains the scanned result
argument:
-i : Ip address of target machine
-p : Ports to be scanned
-t : Which type of scan you need to use
     TCP - Transmission Control Protocol
     UDP - User Datagram Protocol
     COM - Comprehensive
-T : Speed of the scan T1,T2,T3,T4,T5
-j : The result will generated as json file

If you want to know more about nmap just visit https://nmap.org/docs.html
""")
parser.add_argument('-i',type=str,help='Ip address of target machine')
parser.add_argument('-p',type=str,help='Ports to scanned',nargs='?',const='1-1024')
parser.add_argument('-t',type=str,help='The type of scanning protocol',nargs='?', const='-sV')
parser.add_argument('-T',type=str,nargs='?', const='T4',help='This is the speed of the scan T1-T5 limit')
parser.add_argument('-j',type=str,help='this is the file path to create scan result of json')
args = parser.parse_args()



def nmap_scanner():
    """This function is used to scan the ports

    Returns:
        _dict_: _It contains the all scanned results_
    """
    scan=nmap.PortScanner()
    ports = ''
    file_path =args.j
    if args.p:
        ports+=args.p
    else:
        ports = '1-1000'
    if args.T:
        scan_speed = args.T
    else:
        scan_speed = '-T4'
    scan_type=''
    if args.t:
        if args.t == 'TCP':
            scan_type+='-v -sV'
        elif args.t == 'UDP':
            scan_type+='-v -sU'
        elif args.t == 'COM':
            scan_type+='-v -sS -sV -sC -A -O'
        else:
            return 'Invalid protocol just type -h, --help'
    else:
        scan_type+='-sV'
    try:
        
        ip_address = str(socket.gethostbyname(args.i))
        print("Scan has been started  ")
        for i in range(20):
            sys.stdout.write("\r{0}>result=".format("-"*i))
            sys.stdout.flush()
            time.sleep(0.3)
        scan_result = scan.scan(ip_address,ports,arguments=f'{scan_type} {scan_speed}')
        if file_path and scan_result:
            file_name = f"Scanned_result{uuid.uuid4()}.json"
            with open(os.path.join(file_path,file_name),'w+') as file:
                json.dump(scan_result,file)
        scan.command_line()
        return scan_result
    except Exception as _error:
        print(_error)

if __name__ == '__main__':
    print(nmap_scanner(),end='\n')





 