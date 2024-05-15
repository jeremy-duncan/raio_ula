from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptRouteInfo, ICMPv6NDOptPrefixInfo
import subprocess
import socket
import ctypes
import ipaddress

# List to store prefixes that have been added
added_prefixes = []

#prefix checking for ULA fc00:/7
subnet = "fc00::"
prefixlen = 7

def handle_icmpv6(packet):
    global added_prefixes
    current_prefixes = []
    for opt in packet[ICMPv6ND_RA].iterpayloads():
        #we are looking for RIOS now!
        if isinstance(opt, ICMPv6NDOptRouteInfo):
            pref = opt.prefix
            preflen = opt.plen
            rlife = opt.rtlifetime
            current_prefixes.append((pref, preflen))
            print(f"{pref}/{preflen} and {rlife} seconds")
            output = subprocess.check_output('netsh interface ipv6 show prefixpolicies', shell=True).decode()
            if pref in output:
                print(f"The prefix {pref}/{preflen} is in the Windows prefix policies table.")
            #check if prefix in the fc00::/7
            else:
                if is_ipv6_in_subnet(pref, subnet, prefixlen):
                    print(f"The address {pref} is within the {subnet}/{prefixlen} range, adding now")
                    subprocess.call(f"netsh int ipv6 add prefixpolicy prefix={pref}/{preflen} precedence=45 label=14 store=active")
                    added_prefixes.append((pref, preflen))
                else:
                    print(f"The address {pref} is not in the {subnet}/{prefixlen} range.")
            # Check if lifetime has expired
            if rlife == 0:
                remove_prefix_policy(pref, preflen)
        #we are looking for PIO instead now!
        elif isinstance(opt, ICMPv6NDOptPrefixInfo):
            pref = opt.prefix
            preflen = opt.prefixlen
            rlife = opt.validlifetime
            current_prefixes.append((pref, preflen))
            print(f"{pref}/{preflen} and {rlife} seconds")
            output = subprocess.check_output('netsh interface ipv6 show prefixpolicies', shell=True).decode()
            if pref in output:
                print(f"The prefix {pref}/{preflen} is in the Windows prefix policies table.")
            #check if prefix in the fc00::/7
            else:
                if is_ipv6_in_subnet(pref, subnet, prefixlen):
                    print(f"The address {pref} is within the {subnet}/{prefixlen} range, adding now")
                    subprocess.call(f"netsh int ipv6 add prefixpolicy prefix={pref}/{preflen} precedence=45 label=14 store=active")
                    added_prefixes.append((pref, preflen))
                else:
                    print(f"The address {pref} is not in the {subnet}/{prefixlen} range.")
            if rlife == 0:
                remove_prefix_policy(pref, preflen)
    # Check if any prefixes need to be removed
    for pref, preflen in added_prefixes:
        if (pref, preflen) not in current_prefixes:
            print(f"The prefix {pref}/{preflen} is no longer seen - removing now.")
            remove_prefix_policy(pref, preflen)

def is_ipv6_in_subnet(address, pref, preflen):
    # Convert IPv6 address and subnet to integers
    addr_int = int(ipaddress.IPv6Address(address))
    subnet_int = int(ipaddress.IPv6Network(f"{pref}/{preflen}", strict=False).network_address)

    # Check if address is within the subnet
    return (addr_int & subnet_int) == subnet_int

def remove_prefix_policy(pref, preflen):
    print(f"Running this command: netsh int ipv6 del prefixpolicy prefix={pref}/{preflen}")
    try:
        output = subprocess.check_output(f"netsh int ipv6 del prefixpolicy prefix={pref}/{preflen}", shell=True, stderr=subprocess.STDOUT)
        print(f"Command output: {output}")
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error {e.returncode}: {e.output}")
    added_prefixes.remove((pref, preflen))

#Privilege warning

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
