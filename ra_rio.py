from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptRouteInfo
import subprocess

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

# Start sniffing
sniff(lfilter=lambda pkt: IPv6 in pkt and ICMPv6ND_RA in pkt, prn=handle_icmpv6, iface="Ethernet", count=0)
