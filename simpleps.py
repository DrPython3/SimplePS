# -*- coding: utf-8 -*-
'''
                           ---===> SimplePS (Simple PortScanner) <===---
____________________________________________________________________________________________________

AUTHOR:     DrPython3 @ GitHub.com
RELEASE     2
DATE:       2021 / 02 / 28

INFO:       A basic tool for multi threaded port scanning. It scans an IP or IP range for most
            common services and saves active / available ones to textfiles. Hostnames can be scanned,
            too. Therefor, SimplePS will convert the given hostname to an IP as long as it can be
            resolved.

            No extra software like Nmap is neccessary. Users just need Python 3.8+ and some time.
____________________________________________________________________________________________________

Honor the work, if you like this tool or in case you use it on a regular basis! Donate, plase!
Every donation supports future projects and the maintenance (updates, improvements etc.) of those
already available.
                    BTC: 1GfmbWQHfhA7mXwGuuM9iF467eVUnwHDbx
                    LTC: LdeBaZVUGeyYoFjmo8FMDgT66tyv4yhYJ9
____________________________________________________________________________________________________
'''

# ---[needed modules]---:
import sys
try:
    import os
    import colorama
    import threading
    import socket
    import ipaddress
    from queue import Queue
    from time import sleep
except:
    sys.exit('Error importing needed Python modules!\n' + '#'*38 + '\n'
             + 'Just the requirements.txt for installing those dependencies and\n'
             + 'start SimplePS again.')

# init colorama for further use
colorama.init(autoreset=True)

# ---[needed variables +++ dictionaries +++ etc]---:
TargetsIps = []
TargetsLeft = int(0)
TargetsScanned = int(0)
ServicesFound = int(0)

targets_type = int(0)
scan_threads = int(1)
scan_timeout = float(5.00)

scan_locker = threading.Lock()
scan_queue = Queue()

results_all = str('found.txt')
# following ports will be scanned for the named services ...
services_ports = {
    21:'ftp',
    22:'ssh',
    53:'dns',
    3389:'rdp',
    80:'http',
    443:'https',
    25:'smtp',
    143:'imap',
    23:'telnet',
    445:'smb',
    161:'snmp',
    162:'snmp',
    389:'ldap',
    636:'ldaps',
    137:'netbios',
    139:'netbios',
    427:'slp',
    548:'afp',
    110:'pop3'
}

# ---[logo]---:
logo_main = '''
 ,---.  ,--.                 ,--.       ,------.  ,---.   
'   .-' `--',--,--,--. ,---. |  | ,---. |  .--. ''   .-'  
`.  `-. ,--.|        || .-. ||  || .-. :|  '--' |`.  `-.  
.-'    ||  ||  |  |  || '-' '|  |\   --.|  | --' .-'    | 
`-----' `--'`--`--`--'|  |-' `--' `----'`--'     `-----'  
                      `--'                                
<<=====================================================>>
    SimpleP(ort)S(canner) by DrPython3 @ GitHub.com

#[OPTIONS]:                         (1) Scan single IP
                                    (2) Scan hostname
                                    (3) Scan IP-range
                                    ------------------
                                    (9) EXIT
'''

# ---[functions]---:
def blank():
    '''
    Blank screen whenever needed.

    :return: None
    '''
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    return None


def writer(filename, content):
    '''
    Saves any given content to a certain file.

    :param str filename: output-file
    :param str content: content to save
    :return: True, False
    '''
    try:
        with open(str(filename), 'a+') as output_file:
            output_file.seek(0)
            empty = output_file.read(100)
            if len(empty) > 0:
                output_file.write('\n')
            else:
                pass
            output_file.write(str(content))
        return True
    except:
        return False


def portscanner(targetip):
    '''
    Establishes a connection to a given target using Sockets.

    :param str targetip: ip to scan
    :return: True, False
    '''
    global TargetsScanned
    global ServicesFound
    global TargetsLeft
    scan_ip = str('')
    # prepare socket ...
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.settimeout(scan_timeout)
    # get next ip ...
    scan_ip = str(socket.gethostbyname(targetip))
    try:
        with scan_locker:
            print(colorama.Fore.YELLOW + f'Starting scan for ip: {scan_ip}')
        # scan given target ip for all ports in dictionay ...
        for x in services_ports:
            scan_port = int(x)
            scan_service = str(services_ports[x])
            try:
                with scan_locker:
                    print(colorama.Fore.WHITE + f'Scanning {scan_ip}:{str(scan_port)} for {scan_service}')
                scan = scanner.connect((scan_ip,scan_port))
                results_service = str(f'found_{scan_service}.txt')
                result_output = str(f'{scan_service}, {scan_ip}:{str(scan_port)}')
                with scan_locker:
                    ServicesFound += 1
                    print(colorama.Fore.GREEN + f'Found service: {result_output}')
                    save_found = writer(results_all, result_output)
                    if targets_type == 3:
                        save_service = writer(results_service, result_output)
                    else:
                        pass
                scanner.close()
            except:
                continue
        TargetsScanned += 1
        TargetsLeft -= 1
    except:
        with scan_locker:
            print(colorama.Fore.RED + f'Scanning ip: {str(attack_ip)} failed')
    return None


def scanner_threads():
    '''
    Pulls IPs from queue and processes the portscan.

    :return: None
    '''
    while True:
        next_target = str(scan_queue.get())
        portscanner(next_target)
        scan_queue.task_done()
    return None


def main():
    '''
    Main function for user interaction and starting portscans.

    :return: None
    '''
    global targets_type
    global TargetsIps
    global TargetsLeft
    global scan_threads
    global scan_timeout
    blank()
    print(colorama.Fore.CYAN + logo_main + '\n\n')
    targets_type = int(input(colorama.Fore.WHITE + 'Choose an option, please:    '))
    blank()
    if targets_type == 9:
        sys.exit(colorama.Fore.YELLOW + 'Your choice: EXIT\n' + '#'*17 + '\nBye bye && see you again, mate!\n\n')
    elif targets_type in (1, 2, 3):
        print(colorama.Fore.CYAN + '\n\n--[S*i*m*p*l*e*P*S__S*t*a*r*t*U*p]--\n' + '#'*36 + '\n\n\n')
    else:
        return None
    # get target(s) ...
    if targets_type == 1:
        print(colorama.Fore.YELLOW + 'Enter target IP, e.g. 127.0.0.1:\n')
    elif targets_type == 2:
        print(colorama.Fore.YELLOW + 'Enter target hostname, e.g. mydomain.com:\n')
    elif targets_type == 3:
        print(colorama.Fore.YELLOW + 'Enter target IP-range in CDIR format, e.g. 127.0.0.0/24 (has to end on 0!):\n')
    new_target = str(input())
    if targets_type == 1 or targets_type == 2:
        TargetsIps.append(new_target)
    else:
        print(colorama.Fore.YELLOW + '\n\n\n ... adding targets, please wait!\n')
        try:
            TargetsIps = [str(newip) for newip in ipaddress.IPv4Network(new_target)]
            print(colorama.Fore.GREEN + str(len(TargetsIps)) + ' have been added!')
            print(colorama.Fore.YELLOW + '\n\n\nEnter amount of threads to use, e.g. 10:\n')
            try:
                scan_threads = int(input())
            except:
                scan_threads = int(1)
            print(colorama.Fore.YELLOW + f'\n\nScanner threads set to: {str(scan_threads)}')
        except:
            blank()
            print(colorama.Fore.RED + '\n\nSorry! No targets added ...\nPress [ENTER] to return to main menu!')
            wait_for_user = input()
            return None
    print(colorama.Fore.YELLOW + '\n\n\nEnter defaulf timeout for portscan in seconds, e.g. 5.0:\n')
    try:
        scan_timeout = float(input())
    except:
        scan_timeout = float(5.0)
    print(colorama.Fore.YELLOW + f'\n\nDefault timeout set to: {str(scan_timeout)} seconds')
    print(colorama.Fore.YELLOW + '\n\n\nPress [ENTER] to start!')
    wait_for_user = input()
    TargetsLeft = int(len(TargetsIps))
    # start threads ...
    for _ in range(scan_threads):
        psthread = threading.Thread(target=scanner_threads)
        psthread.daemon = True
        psthread.start()
    # fill queue ...
    for targetip in TargetsIps:
        scan_queue.put(targetip)
    # provide stats in window title ...
    while TargetsLeft > 0:
        try:
            sleep(0.5)
            wintitle = f'LEFT TO SCAN: {str(TargetsLeft)} | SCANNED: {str(TargetsScanned)} | FOUND: {str(ServicesFound)}'
            sys.stdout.write('\33]0;' + str(wintitle) + '\a')
            sys.stdout.flush()
        except:
            pass
    # wait for fall threads to finish ...
    scan_queue.join()
    blank()
    # print results ...
    print(colorama.Fore.YELLOW + f'Scanned: {str(TargetsScanned)}')
    if ServicesFound > 0:
        print(colorama.Fore.GREEN + f'Active services found: {str(ServicesFound)}')
    else:
        print(colorama.Fore.RED + 'No active service found.')
    print(colorama.Fore.YELLOW + '\n\n\nPress [ENTER] to return to main menu!\n')
    wait_for_user = input()
    return None


# ---[the magic starts here]---:
while True:
    main()
