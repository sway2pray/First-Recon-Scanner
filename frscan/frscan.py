from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import subprocess as sub
import argparse
import requests
import json
import re
import os

DEFAULT_SECLISTS_PATH:str = '/usr/share/SecLists'
path_to_seclists:str = ''

def update_seclists_path():
    """Checks for SecLists dictionary path.
    In case of abscence in default location prompts user for path storing
    result in "/home/user/.frscan/config.txt"""

    global path_to_seclists
    path_to_seclists = DEFAULT_SECLISTS_PATH

    if not os.path.isdir(path_to_seclists):
        user_home_path:str = os.path.expanduser("~") + '/.frscan/'

        if not os.path.exists(user_home_path + 'config.txt'):
            print('SecLists not found at default location '+\
                                        f"{path_to_seclists}")

            while True:
                path_to_seclists = input('Enter full path to SecLists:')

                if os.path.isdir(path_to_seclists):
                    break
                print(f'\nInvalid path {path_to_seclists}\n')

            try:
                os.mkdir(user_home_path)
            except Exception as exc:
                print('\nError occured upon dir creation: ', exc)
                return False

            try:
                with open(user_home_path + 'config.txt', 'w',
                                                encoding='utf-8') as file:
                    data:dict = {'SecList_path': path_to_seclists}
                    json.dump(data, file, indent=4)

            except Exception as exc:
                print('\nError occured upon config file creation: ', exc)
                return False
            return path_to_seclists
        
        try:
            with open(user_home_path + 'config.txt', 'r',
                                            encoding='utf-8') as file:
                json_data = json.load(file)
                path_to_seclists = json_data['SecList_path']

        except Exception as exc:
            print('\nError occured upon config file openning: ', exc)
            return False

    return path_to_seclists



def parse_args() -> argparse.Namespace:
    """Parses user passed arguments"""

    parser = argparse.ArgumentParser(description='First Recon Scanner'+\
                                    ' - simple automation script of basic'+\
                                                            ' recon tasks.')
    
    parser.add_argument('--target',
                        '-t',
                        type=str,
                        help='Target host for scanning')
    parser.add_argument('--webscan',
                        '-wb',
                        type=str,
                        help='List ports for web scan like "-wb 4093,1235,'+\
                                                                    '9999"')
    parser.add_argument('--protocol',
                        '-p',
                        type=str,
                        default='http',
                        help='Set web protocol to use "-p https". Default is http.')
    parser.add_argument('--verbose',
                        '-v',
                        action='store_true',
                        help='Prints output of subprograms')
    return parser.parse_args()

def is_target_pings(args:argparse.Namespace) -> bool:
    """Pinging target to check if it's alive"""

    try:
        result = sub.run(
            ['ping', '-c', '3', args.target],  # -c 3: Send 3 packets
            capture_output=True,
            text=True,
            timeout=10,
            check=False)
        return True if result.returncode == 0 else False
    except sub.TimeoutExpired:
        return False
    except Exception as exc:
        return False

def nmap_get_ports(stdout, args:argparse.Namespace) -> tuple:
    """Gets open TCP port numbers for subprograms to run their scans on"""

    print("\nStarted initial nmap scan to get open tcp ports")
    ports:list = []
    
    try:
        sub.run(['sudo',
                'nmap',
                args.target,
                '-p-',
                '-Pn',
                '--min-rate',
                '1000',
                '--max-rtt-timeout',
                '1000ms',
                '--max-retries',
                '5',
                '-oN',
                'results/0_nmap_ports.txt'], check=False, stdout=stdout)

    except Exception as e:
        return ([], e)
        
    with open('results/0_nmap_ports.txt', 'r', encoding='utf-8') as file:
        content:str = file.read()
        ports:list = re.findall(r'\d+(?=\/)', content)

    print('\nPorts found:', ','.join(ports))
    return (ports, True)

def nmap_scan(stdout, args:list) -> list:
    """Performs nmap scan with specified args list"""

    print('\nScan launched with params:\n\t', ' '.join(args))
    try:
        sub.run(args, check=False, stdout=stdout)
        print(f'\nScan finished at "{args[-1]}"')        
        return []
    except Exception as exc:
        return [args, exc]

def nmap_scans(stdout, args:argparse.Namespace, ports:list):
    """Launching several nmap scans on diffrent threads and aggregates results
    in one file"""

    print('\nLaunching nmap scans:')
    requests:list = [[  'sudo',
                        'nmap',
                        args.target,
                        '-Pn',
                        '-sC',
                        '-sV',
                        '-oN',
                        'results/1.1_nmap_sCsV.txt'],

                    [   'sudo',
                        'nmap',
                        args.target,
                        '-Pn',
                        '-p53,69,111,123,137,161,500,514,520',
                        '-sUV',
                        '-oN',
                        'results/1.2_nmap_UDP.txt'
                    ]                    
    ]

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures:list = [executor.submit(nmap_scan, stdout, requests[n])
                                        for n in range(len(requests))]
        results = [f.result() for f in as_completed(futures)]
    
    for result in results:
        if result:
            with open(result[0][-1], 'a', encoding='utf-8') as file:
                file.write('\n Catched an error: ' + str(result[1]))

def get_web_ports(all_ports:list) -> list:
    """Returns 443 and 80 ports from list if exists"""

    return [port for port in all_ports if port == '80' or port == '443']

def is_fuzzable(stdout, args:argparse.Namespace, port) -> bool:
    """Checks for 200 status code return from target, otherwise negates"""

    try:
        response = requests.get(f'{args.protocol}://{args.target}:{port}', timeout=10)
        return response.status_code == 200
    except requests.RequestException:
        return False

def fuzz(stdout, args:argparse.Namespace, port:str, fuzz_dict:str) -> tuple:
    """Performs web fuzzing with passed dictionary"""

    if not os.path.isfile(f'{path_to_seclists}/Discovery/Web-Content/'+\
                                                    f'{fuzz_dict}.txt'):
        return(f"Path to dictionary {path_to_seclists}/Discovery/Web-Content"+\
                                            f"/{fuzz_dict}.txt doesn't exist")

    fuzz2status:dict = {}
    fuzz_commands:list = []
    if not is_fuzzable(stdout, args, port):
        return (f"\n{args.protocol}://{args.target}:{port} didn't respond with "+\
            "200 code or reached 10 seconds time interval. Fuzz aborted.\n")

    print(f'\nFuzzing on "{args.protocol}://{args.target}:{port}/FUZZ"\n',
            f'with "{path_to_seclists}/Discovery/Web-Content/{fuzz_dict}.txt"')
    try:
        sub.run(['ffuf',
                '-w',
                f'{path_to_seclists}/Discovery/Web-Content/{fuzz_dict}.txt',
                '-u',
                f'{args.protocol}://{args.target}:{port}/FUZZ',
                '-ic',
                '-c',
                '-o',
                f'tmp/{fuzz_dict}.json',
                '-of',
                'json'], check=False, stdout=stdout, stderr=stdout)

    except Exception as exc:
        return (exc)
    
    try:
        with open(f'tmp/{fuzz_dict}.json', 'r', encoding='utf-8') as file:
            content:dict = json.load(file)
            results:list = content['results']
            fuzz_commands.append(content['commandline'])

            for key in results:
                fuzz2status[key['input']['FUZZ']] = key['status']
    except Exception as exc:
        return (exc)

    
    return (fuzz_commands, fuzz2status)

def web_scans(stdout, args:argparse.Namespace, ports:list=[]):
    """Launches fuzzes with different dictionaries on several threads"""

    print('\nStarted web scans.')

    if args.webscan:
        ports = args.webscan.split(',')
    else:
        ports = get_web_ports(ports)
    print('\tWeb ports to scan:', ', '.join(ports))

    results:dict = {}
    fuzz2status:dict = {}
    fuzz_commands:list = []
    
    # TODO Could optimize by threading each port
    for port in ports:
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_1 = executor.submit(fuzz, stdout, args, port, "directory-list-2.3-small")
            future_2 = executor.submit(fuzz, stdout, args, port, "raft-large-files")

        for future in as_completed([future_1, future_2]):
            result = future.result()
            
            if len(result) > 2:
                print(f'\nFuzzing failed with: {result}')
                continue
            
            fuzz_commands += result[0]
            fuzz2status = fuzz2status | result[1]
        results[port] = (fuzz_commands, fuzz2status)

    with open('results/2_web_fuzzing.txt', 'w', encoding='utf-8') as file:
        for port in results:
            output:str  = ''
            output += f'\nPort {port}:\n'

            if not results[port]:
                if len(results[port]) == 1:
                    output += f'\t{results[port][0]}, fuzz aborted.\n'
                                    
                output += f"\t{args.protocol}://{args.target}:{port} didn't"+\
                                " respond with 200 code or reached 10 seconds"+\
                                " time interval. Fuzz aborted.\n"
                
                file.write(output)
                continue

            output += '\tCommands used:\n'
            fuzz2status:dict = dict(sorted(results[port][1].items(),
                                        key=lambda item: item[1]))
            fuzz_commands:list = results[port][0]

            for cmd in fuzz_commands:
                output += '\t' + cmd + '\n'
            output += '\n'

            for fuzz_res in fuzz2status:
                output += f'\t{fuzz2status[fuzz_res]} {fuzz_res}\n'
            file.write(output)
    print('\nWeb fuzzing finished at "results/2_web_fuzzing.txt"')

def get_smb_ports(all_ports:list) -> list:
    """Returns 139 and 445 ports from list if exists"""

    return [port for port in all_ports if port == '139' or port == '445']

def nxc_smb(args:argparse.Namespace, username:str):
    """Checks for SMB connection"""

    # clear nxc cache to avoid errors
    sub.run(['rm', '-rf', '/tmp/nxc_hosted'], check=True)

    try:
        output = sub.run(['nxc',
                        'smb',
                        f'{args.target}',
                        '-u',
                        f'{username}',
                        '-p',
                        ''], check=False, capture_output=True, text=True)
        return output

    except Exception as exc:
        return exc

def is_nxc_success_regex(content) -> bool:
    result = re.findall(r'(?s).*(\n.*\[\+\].*)$', content)
    return True if result else False

def get_smb_shares(args:argparse.Namespace, username):
    """Launches nxc with --shares flag to list SMB shares"""
    try:
        output = sub.run(['nxc',
                        'smb',
                        f'{args.target}',
                        '-u',
                        f'{username}',
                        '-p',
                        '',
                        '--shares'], check=False, capture_output=True, text=True)
        return output

    except Exception as exc:
        return exc

def smb_rid_brute(stdout, args:argparse.Namespace, username):
    """Performs nxc --rid-brute attack"""
    try:
        output = sub.run(f"nxc smb {args.target} -u '{username}' -p '' " +\
                        "--rid-brute | grep -i 'sidtypeuser' | awk "+\
                        "'{print$6}' | cut -d '\\' -f2 | tee results/3.1_smb_userlist.txt",
                        shell=True, check=False, stdout=stdout, stderr=stdout)
        return output

    except Exception as exc:
        return exc

def is_smb_err_regex(content:str) -> bool:
    """Returns True if 'error' keyword found in text and otherwise"""
    result = re.findall(r'\berror\b', content)
    return True if result else False

def smb_scans(stdout, args:argparse.Namespace, ports:list=[]):
    """Launches smb scans on anonymous and guest accounts trying
    to get connections and possibly extract userlist"""
    output:str = ''
    success_usernames:list = []

    smb_ports:list = get_smb_ports(ports)
    if not smb_ports:
        print("\nSMB service doesn't seems to be running")
        return
    print('\nRunning SMB scans')

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_1 = executor.submit(nxc_smb, args, ' ')
        future_2 = executor.submit(nxc_smb, args, 'guest')

    for future in as_completed([future_1, future_2]):
        result = future.result()
        if is_nxc_success_regex(result.stdout):
            success_usernames.append(result.args[4])

        output += 'Command: ' + ' '.join(result.args) + '\n'
        output += str(result.stdout) + '\n'

    try:
        with open('results/3_smb.txt', 'w', encoding='utf-8') as file:
            file.write(output)
    except Exception as exc:
        print('\nError in writing to file results/3_smb.txt: ', exc)

    if not success_usernames:
        return
    print('\nChecking availible SMB shares')
    output = '\n\nSMB shares\n'

    for username in success_usernames:
        result = get_smb_shares(args, username)

        if type(result) is Exception or is_smb_err_regex(str(result)):
            output += "\nError in nxc smb shares: " + str(result)
            continue

        output += 'Command: ' + ' '.join(result.args) + '\n'
        output += result.stdout + '\n'

    print('\nTrying RID brute to get userlist')
    output += 'Trying RID brute in case of success userlist will be at ' +\
                                            'results/3.1_smb_userlist.txt\n'
    for username in success_usernames:
        result = smb_rid_brute(stdout, args, username)
        if stdout == None:
            print(f'\n{result.stdout}\n{result.stderr}')
    
    try:
        with open('results/3_smb.txt', 'a', encoding='utf-8') as file:
            file.write(output)
    except Exception as exc:
        print('\nError in writing to file results/3_smb.txt: ', exc)


def main():
    """Main function.
    Performs initial checks on user input.
    Passes results from initial nmap scan to other subprograms to run
    on parallel"""

    args:argparse.Namespace = parse_args()

    ##User input checks
    path_to_seclists = update_seclists_path()
    if not path_to_seclists:
        return
    
    if not args.target:
        print('\nSpecify target IP with "-t IP" or "--target IP"')
        return

    if not is_target_pings(args):
        print(f"\nTarget doesn't respond on pings on address {args.target}."+\
                " Aborting program.")
        return

    # add try except
    if not os.path.isdir('tmp'):
        os.mkdir('tmp')
    
    if not os.path.isdir('results'):
        os.mkdir('results')
    ##
    stdout = None if args.verbose else sub.DEVNULL

    ### Single execute flags
    if args.webscan:
        web_scans(stdout, args, [])
        return
    ###
    ports_scan_res = nmap_get_ports(stdout, args)
    if not ports_scan_res[1]:
        print('\nInitial ports scan failed with: ', ports_scan_res[1])
        return

    ports:list = ports_scan_res[0]

    ####All parallel scans 
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_1 = executor.submit(nmap_scans, stdout, args, ports)
        future_2 = executor.submit(web_scans, stdout, args, ports)
        future_3 = executor.submit(smb_scans, stdout, args, ports)
    ####
    print('\nAll scans are finished, results can be viewed in "results" folder.')

if __name__ == '__main__':
    main()