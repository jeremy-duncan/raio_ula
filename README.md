# raio_ula
IPv6 ULA in a Route Information Option (RIO) or a Prefix Information Option (PIO) for Windows in an IPv6 Router Advertisement (RA)

With this python code, the system will listen for RIOs or PIOs in IPv6 RAs:
1. will add a "known-local" ULA prifx if a prefix does not exist in the prefixoptions table - which means it must be in the fd00::/7 prefix boundary
2. will remove if prefix is no longer in an RIO or PIO

# Standard
Follows the updated IETF 6Man draft: [https://datatracker.ietf.org/doc/draft-ietf-6man-rfc6724-update/](https://datatracker.ietf.org/doc/draft-ietf-6man-rfc6724-update/)

# Prerequistes 
This is for Windows, must be using Windows 10 +
* Must have wirehsark w/ NDCap installed - The "manuf" file must be added manually. Recent Wireshark downloads no longer install this file. It can be found at https://www.wireshark.org/download/automated/data/manuf and it needs to be stored in C:\Program Files\Wireshark (thanks Brian!)
* Must have a router that sends the RIO or a PIO in an IPv6 RA 
* Must have Python 3x installed
* Must have scapy 2.5.0 installed - install PIP first
```
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```
* then install scapy:
```
pip install scapy
```

# Run the Application
* Open command line as an Admin - MUST HAVE ADMIN PRIV - cmd.exe
* start:
```
python ra_rio.py
```

add and remove PIOs and RIOs in your network and watch the fun!
* If there is no output after starting it, then your RAs don't have RIOs or PIOs
* can add manually assigned or DHCPv6 assigned address (if no RA exists) thanks to code provided by Brian Carpenter 
* once an RIO or PIO is seen (and it falls in the fd00::/7 prefix), it will be added to the Windows prefixpolicy table. To view that table run this command from a Windows command line:
```
netsh interface ipv6 show prefixpolicies
```
# To Do
* fix thew static address removal function per issue #2
