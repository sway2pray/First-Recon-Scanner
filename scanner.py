from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess as sub
import argparse
import requests
import json
import re
import os

PATH_TO_SECLISTS = '/home/k20/htools/SecLists'

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='A First Recon Scanner')
    
    parser.add_argument('--target',
                        '-t',
                        type=str,
                        help='Target host for scanning')
    parser.add_argument('--webscan',
                        '-wb',
                        type=str,
                        help="""List ports for web scan like "-wb 4093,1235,
                                9999" """)
    parser.add_argument('--protocol',
                        '-p',
                        type=str,
                        default='http',
                        help='Set web protocol to use "-p https". Defualt is http')
    parser.add_argument('--verbose',
                        '-v',
                        action='store_true',
                        help='Prints output of subprograms')
    parser.add_argument('--veryverbose',
                        '-vv',
                        action='store_true',
                        help='Prints all output of subprograms')
                        
    return parser.parse_args()

def is_target_pings(args:argparse.Namespace) -> bool:
    try:
        result = sub.run(
            ['ping', '-c', '3', args.target],  # -c 3: Send 3 packets
            capture_output=True,
            text=True,
            timeout=10
        )
        return True if result.returncode == 0 else False
    except sub.TimeoutExpired:
        return False
    except Exception as e:
        return False

def nmap_get_ports(stdout, args:argparse.Namespace) -> tuple:
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
                '1_nmap_ports.txt'], stdout=stdout)

    except Exception as e:
        return ([], e)
        
    with open('results/1_nmap_ports.txt', 'r', encoding='utf-8') as file:
        content:str = file.read()
        ports:list = re.findall(r'\d+(?=\/)', content)

    return (ports, True)

def nmap_scans(stdout, args:argparse.Namespace, ports:list):
    # TODO
    ports_str = '-p'
    
    for port in ports:
        ports_str += str(port) + ','
    ports_str = ports_str[:-1]

    sub.run(['sudo',
            'nmap', args.target, ports_str, '-Pn',
            '-sC',
            '-sV',
            '-oN',
            'results/1.1_nmap_sCsV.txt'], stdout=stdout)

def get_web_ports(all_ports:list) -> list:
    return [port for port in all_ports if port == '80' or port == '443']

def is_fuzzable(stdout, args:argparse.Namespace, port) -> bool:
    try:
        response = requests.get(f'{args.protocol}://{args.target}:{port}', timeout=10)
        return response.status_code == 200
    except requests.RequestException:
        return False

def fuzz(stdout, args:argparse.Namespace, port:str, fuzz_dict:str):
    if not os.path.isfile(f'{PATH_TO_SECLISTS}/Discovery/Web-Content/'+\
                                                    f'{fuzz_dict}.txt'):
        return(f"Path to dictionary {PATH_TO_SECLISTS}/Discovery/Web-Content"+\
                                            f"/{fuzz_dict}.txt doesn't exist")

    fuzz2status:dict = {}
    fuzz_commands:list = []
    if not is_fuzzable(stdout, args, port):
        return (f"\n{args.protocol}://{args.target}:{port} didn't respond with "+\
            "200 code or reached 10 seconds time interval. Fuzz aborted.\n")

    try:
        sub.run(['ffuf',
                '-w',
                f'{PATH_TO_SECLISTS}/Discovery/Web-Content/{fuzz_dict}.txt',
                '-u',
                f'{args.protocol}://{args.target}:{port}/FUZZ',
                '-ic',
                '-c',
                '-o',
                f'tmp/{fuzz_dict}.json',
                '-of',
                'json'], stdout=stdout)

    except Exception as e:
        return (e)

    with open(f'tmp/{fuzz_dict}.json', 'r', encoding='utf-8') as file:
        content:dict = json.load(file)
        results:list = content['results']
        fuzz_commands.append(content['commandline'])

        for key in results:
            fuzz2status[key['input']['FUZZ']] = key['status']
    
    return (fuzz_commands, fuzz2status)

def web_scans(stdout, args:argparse.Namespace, ports:list=[]):
    if args.webscan:
        ports = args.webscan.split(',')
    else:
        ports = get_web_ports(ports)
        print('Web ports to scan:', ', '.join(ports))

    results:dict = {}
    fuzz2status:dict = {}
    fuzz_commands:list = []
    
    # TODO Could optimize by threading each port
    for port in ports:
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_1 = executor.submit(fuzz, stdout, args, port, "common") #directory-list-2.3-smallping 
            future_2 = executor.submit(fuzz, stdout, args, port, "common") #raft-large-files

        for future in as_completed([future_1, future_2]):
            result = future.result()
            
            if len(result) > 2:
                print(f'\nFuzzing failed with: {result}')
                return
            
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

def main():
    args:argparse.Namespace = parse_args()

    if not args.target:
        print('\n Specify target IP with "-t IP" or "--target IP"')
        return

    if not is_target_pings(args):
        print(f"\nTarget doesn't respond on pings on address {args.target}."+\
                " Aborting program.")
        return

    if not os.path.isdir('tmp'):
        os.mkdir('tmp')
    
    if not os.path.isdir('results'):
        os.mkdir('results')

    stdout = None if args.verbose else sub.DEVNULL

    # Single execute flags
    if args.webscan:
        web_scans(stdout, args, [])
        return
    
    ports_scan_res = nmap_get_ports(stdout, args)
    if not ports_scan_res[1]:
        print('\nInitial ports scan failed with: ', ports_scan_res[1])
        return

    ports:list = ports_scan_res[0]

    # All parallel scans 
    
    #nmap_scans(stdout, args, ports)

    web_scans(stdout, args, ports)
    
    #print(args)

if __name__ == '__main__':
    main()