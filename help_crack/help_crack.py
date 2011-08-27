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
import gzip

base_url   = 'http://wpa-sec.stanev.org/'
help_crack = base_url + 'hc/help_crack.py'
wpa_cap    = base_url + 'cap/wpa.cap.gz'
get_work   = base_url + '?get_work'
put_work   = base_url + '?put_work'

def md5file(filename):
    md5 = hashlib.md5()
    try:
        with open(filename, 'rb') as f: 
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
	    localfile = open(filename, 'wb')
    except Exception, e:
        return False
    localfile.write(response.read())
    localfile.close()
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

def which(program):
    def is_exe(fpath):
        return os.path.exists(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return False

def check_tools():
    if not which('aircrack-ng'):
        print 'No aircrack-ng found'
        exit(1)

def get_gz(gzurl):
    gzname = gzurl.split('/')[-1]
    name = gzname.rsplit('.', 1)[0]
    remotemd5 = get_url(gzurl+'.md5')
    if not remotemd5:
        print 'Can\'t download '+gzurl+'.md5'
        return
    localmd5 = md5file(gzname)
    if remotemd5 != localmd5:
        print 'Downloading ' + gzname
        if download(wpa_cap, gzname):
            if md5file(gzname) == remotemd5:
                try:
                    f = open(name, 'wb')
                    fgz = gzip.open(gzname, 'rb')
                    f.write(fgz.read())
                    f.close()
                    fgz.close()
                except Exception, e:
                    print gzname +' extraction failed'
                    exit(1)
                print name + ' downloaded successfully'
            else:
                print gzname + ' remote md5 mismatch'
                exit(1)
        else:
            print gzname + ' download failed'
            exit(1)

print '''
help_crack, distributed WPA cracker, v0.1
    Usage: ./help_crack : download wpa.cap and wordlist then start cracking, or
           ./help_crack dictionary.txt : to use your own dictionary'''

#check if custom dictionary is passed
cust_dict = ''
if len(sys.argv) == 2:
    if not os.path.exists(sys.argv[1]):
        print 'Could not find custom dictionary'
        exit(1)
    else:
        cust_dict = sys.argv[1]

check_version()
check_tools()
get_gz(wpa_cap)
