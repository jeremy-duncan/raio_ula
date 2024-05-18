from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptRouteInfo, ICMPv6NDOptPrefixInfo
import subprocess
import socket
import ctypes
import ipaddress
import os
import sys


# List to store prefixes that have been added
added_prefixes = []

#prefix checking for ULA fc00:/7
subnet = "fc00::"
prefixlen = 7

def handle_icmpv6(packet):
	global added_prefixes
	current_prefixes = []
	for opt in packet[ICMPv6ND_RA].iterpayloads():
		#we are looking for RIOs now!
		if isinstance(opt, ICMPv6NDOptRouteInfo):
			pref = opt.prefix
			preflen = opt.plen
			rlife = opt.rtlifetime
			current_prefixes.append((pref, preflen))
			print(f"RIO advertised prefix seen on the wire --> {pref}/{preflen} and {rlife} seconds")
			output = subprocess.check_output('netsh interface ipv6 show prefixpolicies', shell=True).decode()
			if pref in output:
				print(f"The RIO advertised prefix {pref}/{preflen} is already in the Windows prefix policies table, moving along.")
			#check if prefix in the fc00::/7
			else:
				if is_ipv6_in_subnet(pref, subnet, prefixlen):
					print(f"The RIO advertised address {pref} is within the {subnet}/{prefixlen} range, adding now")
					subprocess.call(f"netsh int ipv6 add prefixpolicy prefix={pref}/{preflen} precedence=45 label=14 store=active")
					added_prefixes.append((pref, preflen))
				else:
					print(f"The RIO advertised address {pref} is not in the {subnet}/{prefixlen} range.")
			# Check if lifetime has expired
			if rlife == 0:
				remove_prefix_policy(pref, preflen)
				
		#we are looking for PIOs instead now!
		elif isinstance(opt, ICMPv6NDOptPrefixInfo):
			pref = opt.prefix
			preflen = opt.prefixlen
			rlife = opt.validlifetime
			current_prefixes.append((pref, preflen))
			print(f"RIO advertised prefix seen on the wire --> {pref}/{preflen} and {rlife} seconds")
			output = subprocess.check_output('netsh interface ipv6 show prefixpolicies', shell=True).decode()
			if pref in output:
				print(f"The PIO advertised prefix {pref}/{preflen} is already in the Windows prefix policies table, moving along.")
			#check if prefix in the fc00::/7
			else:
				if is_ipv6_in_subnet(pref, subnet, prefixlen):
					print(f"The PIO advertised address {pref} is within the {subnet}/{prefixlen} range, adding now")
					subprocess.call(f"netsh int ipv6 add prefixpolicy prefix={pref}/{preflen} precedence=45 label=14 store=active")
					added_prefixes.append((pref, preflen))
				else:
					print(f"The PIO advertised address {pref} is not in the {subnet}/{prefixlen} range.")
			if rlife == 0:
				remove_prefix_policy(pref, preflen)
		else:
			static()
	

	# Check if any prefixes need to be removed
	for pref, preflen in added_prefixes:
		if (pref, preflen) not in current_prefixes:
			remove_prefix_policy(pref, preflen)
	
	looprestart()
	
def is_ipv6_in_subnet(address, pref, preflen):
	# Convert IPv6 address and subnet to integers
	addr_int = int(ipaddress.IPv6Address(address))
	subnet_int = int(ipaddress.IPv6Network(f"{pref}/{preflen}", strict=False).network_address)

	# Check if address is within the subnet
	return (addr_int & subnet_int) == subnet_int

def remove_prefix_policy(pref, preflen):
	print(f"The ULA prefix {pref}/{preflen} is no longer seen - removing now.")
	print(f"Running this command: netsh int ipv6 del prefixpolicy prefix={pref}/{preflen}")
	try:
		output = subprocess.check_output(f"netsh int ipv6 del prefixpolicy prefix={pref}/{preflen}", shell=True, stderr=subprocess.STDOUT)
		print(f"Command output: {output}")
	except subprocess.CalledProcessError as e:
		print(f"Command failed with error {e.returncode}: {e.output}")
	added_prefixes.remove((pref, preflen))

def is_ula(a):
	"""Test for ULA"""
	return (a.is_private and not a.is_link_local
			 and not a.is_loopback
			 and not a.is_unspecified)
def askexit():
	"""Get me outa here"""
	input("Press Enter to Exit.")
	exit()
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

####################################################
# Get list of ULAs from Brian Carpender's enable_ula.py
####################################################
def static():
	my_os = sys.platform

	if my_os == "win32":
		print("You are running on Windows.")
	else:
		print("Assuming a POSIX-compliant operating system.")
		try:
			import netifaces
		except:
			print("Could not import netifaces - please install with pip or apt-get.")
			askexit()

	####################################################
	# Get list of ULAs
	#
	# This code is very o/s dependent
	####################################################

	ulas = []
	if my_os == "win32":
		#Windows
			  
		_addrinfo = socket.getaddrinfo(socket.gethostname(),0)
		for _af,_temp1,_temp2,_temp3,_addr in _addrinfo:
			if _af == socket.AF_INET6:
				_addr,_temp,_temp,_zid = _addr  #get first item from tuple
				
				if not '%' in _addr:
					_loc = ipaddress.IPv6Address(_addr)
					# Now test for  ULA address
					if is_ula(_loc):
						ulas.append(_loc)  # save ULA
			
	else: #assume POSIX     
		ifs = netifaces.interfaces()
		for interface in ifs:
			config = netifaces.ifaddresses(interface)
			if netifaces.AF_INET6 in config.keys():
				for link in config[netifaces.AF_INET6]:
					if 'addr' in link.keys():
						_addr = link['addr']
						if not '%' in _addr:
							_loc = ipaddress.IPv6Address(_addr)
							# Now test for ULA
							if is_ula(_loc):
								ulas.append(_loc)  # save ULA

	if not len(ulas):
		print("No Statically (or non RA ULA prefixes) found.")

	# Convert addresses to prefixes as text strings
	prefs = []

	for a in ulas:
		#strip to /48
		a = ipaddress.IPv6Address(a.packed[:6]+bytes.fromhex('00000000000000000000'))
		p = str(a) + "/48"
		if not p in prefs:
			prefs.append(p)
	ula_added = []
	for p in prefs:
		ula_added.append(p)
		print(f"ULA prefix(es) found: {p}")
		output = subprocess.check_output('netsh interface ipv6 show prefixpolicies', shell=True).decode()
		if p in output:
			print(f"The static prefix of {p} is already in the Windows prefix policies table, moving along.")			
		else:
			cmd = "netsh interface ipv6 add prefixpolicy " + p + " 45 14 active"
			#(This MUST be 'active' because doing otherwise triggers a serious
			# Windows bug that clears the rest of the policy table on the
			# next boot.)
			subprocess.call(cmd)

	##this part is not working... can't delete the static one from the table currently
	print(f"statically assigned prefs is run --> {ula_added}")
	#check_static_ipv6_removed(ula_added)
		

	print("Current prefix policies:")
	subprocess.call(f"netsh interface ipv6 show prefixpolicies")

	
def check_static_ipv6_removed(ula_added):
# Run the command to check if the IPv6 address is unplumbed
	result = subprocess.run(["netsh", "interface", "ipv6", "show", "addresses"], capture_output=True, text=True)
	output = result.stdout
	ulas = ula_added[0]
# Check if the prefix is no longer seen - if not in output delete from table
	if f"{ulas}" not in output:
		subprocess.check_output(f"netsh int ipv6 del prefixpolicy prefix={ulas}", shell=True, stderr=subprocess.STDOUT)



def looprestart():
	print("All done --- Restarting Loop.")
	print("------------------------------------------------------------------------")
	print("------------------------------------------------------------------------")
	print("************* Press CTRL + C to exit this loop *************************")
	print("------------------------------------------------------------------------")
	print("------------------------------------------------------------------------")
	
# Start sniffing
sniff(lfilter=lambda pkt: IPv6 in pkt and ICMPv6ND_RA in pkt, prn=handle_icmpv6, iface=ifaces, count=0)
