# First Recon Scan - A simple automation script of basic recon tasks.

## What it does:
-Scans for nmap ports TCP/UDP with different depth.

-Performs web fuzzing with several dictionaries.

-Checks for guest and anonymous logins to SMB

-Enumerates SMB shares if availible and extracts userlists

Most scans run in parallel, so it's faster then most of the manual work.

Written in Python standart libs.

## Planning to add:
Redis, WinRM, LDAP, SNMP, vhost enumeration and other.

## Prerequisites & Install
### CLI tools: nmap, ffuf, ping, netexec (nxc)
### Dictionaries - [SecLists](https://github.com/danielmiessler/SecLists/tree/master)

1.Git clone this repo.

2.Install with pip.
```bash
cd 'First-Recon-Scan'/

pip install -e .
```

## Usage
```bash
frscan [-h] [-t TARGET_IP]
```

options:

-h, --help                Show this help message and exit

--target, -t TARGET       Target host for scanning

--webscan, -wb WEBSCAN    List ports for only web scan like "-wb 4093,1235,9999"

--protocol, -p PROTOCOL   Set web protocol to use "-p https". Default is http.

--verbose, -v             Prints output of subprograms

## Credits
NMAP https://github.com/nmap/nmap

FFUF https://github.com/ffuf/ffuf

SecLists https://github.com/danielmiessler/SecLists/tree/master

NetExec https://github.com/Pennyw0rth/NetExec
