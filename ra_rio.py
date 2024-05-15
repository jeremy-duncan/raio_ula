from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptRouteInfo
import subprocess
import socket
import ctypes

# List to store prefixes that have been added
added_prefixes = []

def handle_icmpv6(packet):
    global added_prefixes
    current_prefixes = []
    for opt in packet[ICMPv6ND_RA].iterpayloads():
        if isinstance(opt, ICMPv6NDOptRouteInfo):
            pref = opt.prefix
            preflen = opt.plen
            rlife = opt.rtlifetime
            current_prefixes.append((pref, preflen))
            print(f"{pref}/{preflen} and {rlife} seconds")
            output = subprocess.check_output('netsh interface ipv6 show prefixpolicies', shell=True).decode()
            if pref in output:
                print(f"The prefix {pref}/{preflen} is in the Windows prefix policies table.")
            else:
                if pref.startswith("fd"):
                    print(f"The prefix {pref}/{preflen} is within the fd0::/8 range - adding now.")
                    subprocess.call(f"netsh int ipv6 add prefixpolicy prefix={pref}/{preflen} precedence=45 label=14 store=active")
                    added_prefixes.append((pref, preflen))
                else:
                    print(f"The prefix {pref}/{preflen} is not in the fd0::/8 range - skipping.")
    # Check if any prefixes need to be removed
    for pref, preflen in added_prefixes:
        if (pref, preflen) not in current_prefixes:
            print(f"The prefix {pref}/{preflen} is no longer seen - removing now.")
            remove_prefix_policy(pref, preflen)

def remove_prefix_policy(pref, preflen):
    print(f"Running this command: netsh int ipv6 del prefixpolicy prefix={pref}/{preflen}")
    try:
        output = subprocess.check_output(f"netsh int ipv6 del prefixpolicy prefix={pref}/{preflen}", shell=True, stderr=subprocess.STDOUT)
        print(f"Command output: {output}")
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error {e.returncode}: {e.output}")
    added_prefixes.remove((pref, preflen))

# Privilege warning

if not ctypes.windll.shell32.IsUserAnAdmin():
    print("Will not work without Administrator privilege.")
    exit()

# Prepare interfaces names as scapy likes them.
# (Ideally, we'd repeat this process at intervals, and restart
# the sniffer if anything changes.)

# First, find all active interfaces
zzzz = []
for af,_,_,_,addr in socket.getaddrinfo(socket.gethostname(),0):
    if af == socket.AF_INET6:
        addr,_,_,zid = addr  #get first item from tuple
        if '%' in addr:
            #this applies on Windows for Python before 3.7
            addr, zid = addr.split('%') #strip any Zone ID
            zid = int(zid)
        if zid and not zid in zzzz:
            zzzz.append(zid)

# Second, convert their indexes to the arcane internal Windows format
ifaces = []
for zid in zzzz:
    ifaces.append(str(dev_from_index(zid)))
print("Active interface numbers", zzzz)
print("Interface names for scapy", ifaces)

# Start sniffing
sniff(lfilter=lambda pkt: IPv6 in pkt and ICMPv6ND_RA in pkt, prn=handle_icmpv6, iface=ifaces, count=0)

