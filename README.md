# raio_ula
IPv6 ULA in a Route Information Option (RIO) for Windows in an IPv6 Router Advertisement (RA)
With this python code, the system will listen for RIOs in IPv6 RAs:
1. will add a "known-local" ULA prifx if a prefix does not exist in hte prefixoptions table
2. will remove if prefix is no longer in an RIO

# Standard
Follows the updated IETF 6Man draft: [https://datatracker.ietf.org/doc/draft-ietf-6man-rfc6724-update/](https://datatracker.ietf.org/doc/draft-ietf-6man-rfc6724-update/)

# Prerequistes 
This is for Windows, must be using Windows 10 +
* Must have Python 3x installed
* Must have scapy 2.5.0 installed - install PIP first
** curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
  python get-pip.py
** then install scapy:
```
pip install scapy
```

# Start python code
* Open command line as an Admin - MUST HAVE ADMIN PRIV - cmd.exe
* start:
```
python ra_rio.py
```

add and remove RIOs in your network and watch the fun!
