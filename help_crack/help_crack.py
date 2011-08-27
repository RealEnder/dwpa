#!/usr/bin/python
# The source code is distributed under GPLv3+ license
import sys
import os
import os.path
import stat
import urlparse
import socket
import urllib2
import hashlib

help_crack = 'http://wpa-sec.stanev.org/hc/help_crack.py'
get_work = 'http://wpa-sec.stanev.org/?get_work'
put_work = 'http://wpa-sec.stanev.org/?put_work'

def md5file(filename):
    md5 = hashlib.md5()
    try:
        with open(filename, 'r') as f: 
            for chunk in iter(lambda: f.read(8192), ''): 
                 md5.update(chunk)
    except Exception, e:
        return False
    f.close()
    return md5.hexdigest()

def download(url, filename):
    try:
        response = urllib2.urlopen(url)
    except Exception, e:
        return False

    try:
	    localfile = open(filename, 'w')
    except Exception, e:
        return False

    localfile.write(response.read())
    return True

def get_url(url):
    try:
        response = urllib2.urlopen(url)
    except Exception, e:
        return False
    remote = response.read()
    response.close()
    return remote.strip()

def check_version():
    remotemd5 = get_url(help_crack+'.md5')
    if not remotemd5:
        print 'Can\'t check for new version, continue...'
        return

    if remotemd5 != md5file(sys.argv[0]):
        user = raw_input('New version of help_crack found. Update?[y]:')
        if user == 'y' or user == '':
            if download(help_crack, sys.argv[0]+'.new'):
                if md5file(sys.argv[0]+'.new') == remotemd5:
                    os.rename(sys.argv[0]+'.new', sys.argv[0])
                    os.chmod(sys.argv[0], stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
                    print 'help_crack updated, run again'
                    exit(0)
                else:
                    print 'help_crack remote md5 mismatch'
                    exit(1)
            else:
                print 'help_crack update failed'
                exit(1)


print '''
help_crack, distributed WPA cracker, v0.1
    Usage: ./help_crack : download wordlist and start cracking, or
           ./help_crack dictionary.txt : to use your own dictionary'''

if len(sys.argv) == 2:
    if not os.path.exists(sys.argv[1]):
        print 'Could not find custom dictionary'
        exit(1)
    else:
        cust_dict = sys.argv[1]

check_version()
