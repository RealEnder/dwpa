#!/usr/bin/python
# The source code is distributed under GPLv3+ license
# author: Alex Stanev, alex at stanev dot org
# web: http://wpa-sec.stanev.org

import sys
import os
import platform
import subprocess
import shlex
import stat
import urllib
import hashlib
import gzip
import re
import time
import StringIO

#some base variables
base_url      = 'http://wpa-sec.stanev.org/'
help_crack    = base_url + 'hc/help_crack.py'
help_crack_cl = base_url + 'hc/CHANGELOG'
md5caps       = base_url + 'md5caps/'
get_work_url  = base_url + '?get_work'
put_work_url  = base_url + '?put_work'

#version
hc_ver = '0.7'

def sleepy():
    print 'Sleeping...'
    time.sleep(222)

#validate bssid/mac address
def valid_mac(mac):
    if len(mac) != 17:
        return False
    if not re.match(r'^([a-f0-9]{2}\:?){6}$', mac):
        return False
    return True

#make temp filename
def mk_temp():
    md5s = hashlib.md5()
    while True:
        md5s.update(os.urandom(16))
        md5h = md5s.hexdigest()
        if not os.path.exists(md5h):
            break
    return md5h

#get md5 from local file
def md5file(filename):
    md5s = hashlib.md5()
    try:
        with open(filename, 'rb') as f: 
            for chunk in iter(lambda: f.read(8192), ''):
                md5s.update(chunk)
    except Exception as e:
        print 'Exception: %s' % e
        return False

    return md5s.hexdigest()

#download remote file
def download(url, filename):
    try:
        urllib.urlretrieve(url, filename)
    except Exception as e:
        print 'Exception: %s' % e
        return False

    return True

#get remote content and return it in var
def get_url(url):
    try:
        response = urllib.urlopen(url)
    except Exception as e:
        print 'Exception: %s' % e
        return False
    remote = response.read()
    response.close()

    return remote

#get md5 of current script, compare it with remote and initiate update
def check_version():
    remotemd5 = get_url(help_crack+'.md5')
    if not remotemd5:
        print 'Can\'t check for new version, continue...'
        return

    if remotemd5 != md5file(sys.argv[0]):
        while True:
            user = raw_input('New version of help_crack found. Update[y] or Show changelog[c]:')
            if user == 'c':
                print get_url(help_crack_cl)
                continue
            if user == 'y' or user == '':
                if download(help_crack, sys.argv[0]+'.new'):
                    if md5file(sys.argv[0]+'.new') == remotemd5:
                        try:
                            os.rename(sys.argv[0]+'.new', sys.argv[0])
                            os.chmod(sys.argv[0], stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
                        except Exception as e:
                            print 'Exception: %s' % e
                            #TODO: think of workaround locking on win32
                            if os.name == 'nt':
                                print 'You are running under win32, rename help_crack.py.new over help_crack.py'
                        print 'help_crack updated, run again'
                        exit(0)
                    else:
                        print 'help_crack remote md5 mismatch'
                        return
                else:
                    print 'help_crack update failed'
                    return
            return

#find executable in current dir or in PATH env var
def which(program):
    def is_exe(fpath):
        return os.path.exists(fpath) and os.access(fpath, os.X_OK)

    if os.name == 'nt':
        program += '.exe'
        if os.path.exists(program):
            return program

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ['PATH'].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
        if os.name == 'posix' and is_exe(program):
            return './' + program

    return False

#look for cracking tools, check for their capabilities, ask user
def check_tools():
    tools = []
    if os.name == 'posix':
        t = which('pyrit')
        if t:
            tools.append(t)

    t = which('aircrack-ng')
    if t:
        tools.append(t)
        acp = subprocess.Popen([t, '--help'], stdout=subprocess.PIPE)
        (output, oerr) = acp.communicate()
        if output.find('Hashcat') != -1:
            (bits, linkage) = platform.architecture()
            if bits == '64bit':
                t = which('oclHashcat-plus64')
                if t:
                    tools.append(t)
                t = which('cudaHashcat-plus64')
                if t:
                    tools.append(t)
            else:
                t = which('oclHashcat-plus32')
                if t:
                    tools.append(t)
                t = which('cudaHashcat-plus32')
                if t:
                    tools.append(t)
                    
    if len(tools) == 0:
        print 'No aircrack-ng, pyrit or oclHashcat-plus found'
        exit(1)
    if len(tools) == 1:
        return tools[0]
    
    print 'Choose the tool for cracking:'
    for index, tool in enumerate(tools):
        print '%i: %s' % (index, tool)
    print '9: Quit'
    while 1:
        user = raw_input('Index:')
        if user == '9':
            exit(0)
        try:
            return tools[int(user)]
        except Exception:
            print 'Wrong index'

#check remote md5 of gz, download it on mismatch, decompress
def get_gz(gzurl):
    localmd5 = ''
    gzname = gzurl.split('/')[-1]
    name = gzname.rsplit('.', 1)[0]
    remotemd5 = get_url(gzurl+'.md5')
    if not remotemd5:
        print 'Can\'t download '+gzurl+'.md5'
        return False
    if os.path.exists(gzname):
        localmd5 = md5file(gzname)
    if remotemd5 != localmd5:
        print 'Downloading ' + gzname
        if download(gzurl, gzname):
            if md5file(gzname) == remotemd5:
                try:
                    f = open(name, 'wb')
                    fgz = gzip.open(gzname, 'rb')
                    f.write(fgz.read())
                    f.close()
                    fgz.close()
                except Exception as e:
                    print gzname +' extraction failed'
                    print 'Exception: %s' % e
                    return False
                print name + ' downloaded successfully'
            else:
                print gzname + ' remote md5 mismatch'
                return False
        else:
            print gzname + ' download failed'
            return False
    return name

#get work and remote dict
def get_work_wl():
    work = get_url(get_work_url+'='+hc_ver)
    if work:
        if work == 'No nets':
            return (False, False)

        if work == 'Version':
            print 'Please update help_crack, the interface has changed'
            exit(1)

        gwr = work.split('\\')
        if len(gwr) < 3:
            print 'Server returned bad response. Check for help_crack update.'
            exit(1)

        gwhash = gwr[0]
        gwbssid = gwr[1]
        gwwl = gwr[2]

        if len(gwhash) != 32:
            return (False, False, False)

        if not valid_mac(gwbssid):
            return (False, False, False)

        gwwl = get_gz(gwwl)

        return (gwhash, gwbssid, gwwl)
    else:
        return (False, False, False)

#return results to server
def put_work(pwhash, pwkey):
    data = urllib.urlencode({pwhash: pwkey})
    try:
        response = urllib.urlopen(put_work_url, data)
    except Exception as e:
        print 'Exception: %s' % e
        return False

    remote = response.read()
    response.close()

    if remote != 'OK':
        return False

    return True

#multiplatform lower priority
def low_priority():
    if os.name == 'posix':
        os.nice(10)
    else:
        try:
            import win32api, win32process, win32con

            pid = win32api.GetCurrentProcessId()
            handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
            win32process.SetPriorityClass(handle, win32process.BELOW_NORMAL_PRIORITY_CLASS)
        except Exception as e:
            print 'Exception: %s' % e
            print 'Maybe you lack Python for Windows extensions. Link: http://sourceforge.net/projects/pywin32'


print 'help_crack, distributed WPA cracker, v' + hc_ver
print 'site: ' + base_url

#check if custom dictionary is passed
wordlist = ''
if len(sys.argv) > 1:
    print 'Usage: ./help_crack.py : download capture and wordlist then start cracking'
    exit(1)

check_version()
tool = check_tools()
#lower priority for CPU crackers. Pyrit goes here too
if tool.find('aircrack-ng') != -1 or tool.find('pyrit') != -1:
    low_priority()

rule = ''
#use rules for oclHashcat-plus
#disable it for now
#if tool.find('Hashcat') != -1:
#    if os.path.exists('rules/best64.rule'):
#        rule = '-rrules/best64.rule'

while True:
    (nhash, bssid, wl) = get_work_wl()

    if nhash == False:
        print 'No suitable nets found'
        sleepy()
        continue

    if wl == False:
        print 'Couldn\'t download the wordlist'
        sleepy()
        continue

    #get capture and write it in local file
    gzcap = get_url(md5caps+nhash[0:3]+'/'+nhash+'.gz')
    if not gzcap:
        sleepy()
        continue
    gzstream = StringIO.StringIO(gzcap)
    cap_temp = mk_temp()
    try:
        fgz = gzip.GzipFile(fileobj = gzstream)
        fd = open(cap_temp, 'wb')
        fd.write(fgz.read())
        fd.close()
        fgz.close()
    except Exception as ex:
        print 'Exception: %s' % ex
        sleepy()
        continue

    key_temp = mk_temp()

    #run cracker
    try:
        if tool.find('pyrit') != -1:
            cracker = '%s -i%s -o%s -b%s -r%s attack_passthrough' % (tool, wl, key_temp, bssid, cap_temp)
            subprocess.call(shlex.split(cracker))
        if tool.find('aircrack-ng') != -1:
            cracker = '%s -w%s -l%s -b%s %s' % (tool, wl, key_temp, bssid, cap_temp)
            subprocess.call(shlex.split(cracker))
        if tool.find('Hashcat') != -1:
            subprocess.call(['aircrack-ng', '-Jwpa', cap_temp])
            if not os.path.exists('wpa.hccap'):
                print 'Could not create hccap file with aircrack-ng'
                exit(1)
            try:
                cracker = '%s -m2500 -o%s %s wpa.hccap %s' % (tool, key_temp, rule, wl)
                subprocess.check_call(shlex.split(cracker))
            except subprocess.CalledProcessError as ex:
                if ex.returncode != 1:
                    print 'Cracker %s died with code %i' % (tool, ex.returncode)
                    print 'Check you have CUDA/OpenCL support'
                    exit(1)
    except KeyboardInterrupt as ex:
        print 'Keyboard interrupt'
        if os.path.exists(key_temp):
            os.unlink(key_temp)
        if os.path.exists(cap_temp):
            os.unlink(cap_temp)
        exit(1)

    if os.path.exists(cap_temp):
        os.unlink(cap_temp)

    #if we have key, submit it
    if os.path.exists(key_temp):
        ktf = open(key_temp, 'r')
        key = ktf.readline()
        ktf.close()
        if tool.find('Hashcat') != -1:
            key = key[key.find(':')+1:]
        key = key.rstrip('\n')
        print 'Key for capture hash '+nhash+' is: '+key
        while not put_work(nhash, key):
            print 'Couldn\'t submit key'
            sleepy()
        os.unlink(key_temp)
    else:
        print 'Key for capture hash '+nhash+' not found.'
