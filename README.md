# knock-knock

Nmap wrapper for knocking on ports.

## Usage

Scan 1000 addresses for an open telnet port, save those ip's to ip.txt, and then connect to those ports.<br>
```
./kknock
```
Scan 5000 addresses for an open telnet port and save list of ip's as open23.txt.
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

## Notes

Ctrl-z is overridden, it acts as a next-address button when enumerating.

```
Trying 181.126.131.230...
Connected to 181.126.131.230.ar.ir.
Escape character is '^]'.
Password:
telnet> ^Z
Trying 173.24.222.213...
Connected to 173.24.222.213.
Escape character is '^]'.

192.168.1.255 login:
telnet> ^Z
Trying 124.140.59.129...
Connected to 124.140.59.129.
```
