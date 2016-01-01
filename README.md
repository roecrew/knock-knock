# knock-knock

Nmap wrapper for knocking on ports.

## Usage

Scan 1000 ports for an open telnet port, save those ip's to ip.txt, then connect to those ports.
```
./kknock
```
Scan 5000 ports for an open telnet port and save list of ip's as open23.txt.
```
./kknock -d open23.txt -n 5000
```
Connect to each ip's port 21.
```
./kknock -k open23.txt -p 21
```
Version detect port 22 and save as ver_ip.txt.
```
./kknock -t ip.txt -p 22
```
