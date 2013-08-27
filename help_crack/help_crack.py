#!/usr/bin/python
# The source code is distributed under GPLv3+ license
# author: Alex Stanev, alex at stanev dot org
# web: http://wpa-sec.stanev.org

import sys
import os
import fnmatch
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
get_work_url  = base_url + '?get_work2'
put_work_url  = base_url + '?put_work'

#version
hc_ver = '0.7.3'

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

#get md5 from local file
def md5file(filename):
    md5s = hashlib.md5()
    try:
        with open(filename, 'rb') as f: 
            for chunk in iter(lambda: f.read(8192), ''):
                md5s.update(chunk)
    except Exception as e:
        print 'Exception: %s' % e
        return None

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
        return None
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

    fpath = os.path.split(program)[0]
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

#run external tool and check returncode
def run_tool(tool):
    if not isinstance(tool, basestring):
        return False

    try:
        subprocess.check_call(tool, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as ex:
        return False

    return True

#Hashcat always returns returncode 255
def run_hashcat(tool):
    if not isinstance(tool, basestring):
        return False

    try:
        acp = subprocess.Popen(tool, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = acp.communicate()[0]
    except OSError as ex:
        return False
    if output.find('hashcat') != -1:
        return True

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
        output = acp.communicate()[0]
        if output.find('Hashcat') != -1:
            bits = platform.architecture()[0]
            if bits == '64bit':
                #this is for Hashcat
                t = which('hashcat-cli64')
                if run_hashcat(t):
                    tools.append(t)
                t = which('hashcat-cliAVX')
                if run_hashcat(t):
                    tools.append(t)
                t = which('hashcat-cliXOP')
                if run_hashcat(t):
                    tools.append(t)
                t = which('hashcat-cli64.bin')
                if run_hashcat(t):
                    tools.append(t)
                t = which('hashcat-cliAVX.bin')
                if run_hashcat(t):
                    tools.append(t)
                t = which('hashcat-cliXOP.bin')
                if run_hashcat(t):
                    tools.append(t)
                t = which('hashcat-cli64.app')
                if run_hashcat(t):
                    tools.append(t)
                #this is for oclHashcat-plus
                t = which('oclHashcat-plus64')
                if run_tool(t):
                    tools.append(t)
                t = which('oclHashcat-plus64.bin')
                if run_tool(t):
                    tools.append(t)
                t = which('cudaHashcat-plus64')
                if run_tool(t):
                    tools.append(t)
                t = which('cudaHashcat-plus64.bin')
                if run_tool(t):
                    tools.append(t)
            else:
                #this is for Hashcat
                t = which('hashcat-cli')
                if run_hashcat(t):
                    tools.append(t)
                t = which('hashcat-cli.bin')
                if run_hashcat(t):
                    tools.append(t)
                #this is for oclHashcat-plus
                t = which('oclHashcat-plus32')
                if run_tool(t):
                    tools.append(t)
                t = which('oclHashcat-plus32.bin')
                if run_tool(t):
                    tools.append(t)
                t = which('cudaHashcat-plus32')
                if run_tool(t):
                    tools.append(t)
                t = which('cudaHashcat-plus32.bin')
                if run_tool(t):
                    tools.append(t)
                    
    if len(tools) == 0:
        print 'No aircrack-ng, pyrit, Hashcat or oclHashcat-plus found'
        exit(1)
    if len(tools) == 1:
        return tools[0]
    
    print 'Choose the tool for cracking:'
    for index, ttool in enumerate(tools):
        print '%i: %s' % (index, ttool)
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
                    ftgz = gzip.open(gzname, 'rb')
                    f.write(ftgz.read())
                    f.close()
                    ftgz.close()
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
    if work is not None:
        if work == 'No nets':
            return (False, False, False)

        if work == 'Version':
            print 'Please update help_crack, the interface has changed'
            exit(1)

        gwr = work.split('\\')
        if len(gwr) < 3:
            print 'Server returned bad response. Check for help_crack update.'
            return (False, False, False)

        gwhash = gwr[0]
        gwbssid = gwr[1]
        gwwl = gwr[2]

        if len(gwhash) != 32:
            return (False, False, False)

        if not valid_mac(gwbssid):
            return (False, False, False)

        get_gz(gwwl)

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

#create capture filename and resume file
def create_resume(tnhash, tbssid, twl):
    md5s = hashlib.md5()
    while True:
        md5s.update(os.urandom(16))
        md5h = md5s.hexdigest()
        if not os.path.exists(md5h+'.cap'):
            break
    resc = [tnhash+"\n", tbssid+"\n", twl+"\n"]
    rfd = open(md5h+'.res','w')
    rfd.writelines(resc)
    rfd.close()

    return md5h+'.cap'

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

#check for resume files
def resume_check():
    for fname in os.listdir('.'):
        if fnmatch.fnmatch(fname, '*.res'):
            if os.path.exists(fname.replace('.res', '.cap')):
                rfd = open(fname, 'r')
                resc = rfd.readlines()
                rfd.close()
                if len(resc) >= 3:
                    print 'Resume file %s found' % fname
                    resc[0] = resc[0].replace("\n", '')
                    resc[1] = resc[1].replace("\n", '')
                    resc[2] = resc[2].replace("\n", '')
                    get_gz(resc[2])
                    resc[2] = resc[2].split('/')[-1]
                    resc[2] = resc[2].rsplit('.', 1)[0]
                    return (resc[0], resc[1], resc[2], fname.replace('.res', '.cap'))
                else:
                    print 'Bad resume file contents'            
            else:
                print 'Resume file found, but not capture'
                os.unlink(fname)

    return (None, None, None, None)

print 'help_crack, distributed WPA cracker, v' + hc_ver
print 'site: ' + base_url

wordlist = ''
if len(sys.argv) > 1:
    print 'Usage: ./help_crack.py : download capture and wordlist then start cracking'
    exit(1)

check_version()
tool = check_tools()
#lower priority for CPU crackers. Pyrit goes here too
if tool.find('aircrack-ng') != -1 or tool.find('pyrit') != -1 or tool.find('hashcat-cli') != -1:
    low_priority()

rule = ''
#use rules for oclHashcat-plus
#disable it for now
#if tool.find('Hashcat') != -1:
#    if os.path.exists('rules/best64.rule'):
#        rule = '-rrules/best64.rule'

while True:
    (nhash, bssid, wl, cap_temp) = resume_check()
    if nhash is None:
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
        cap_temp = create_resume(nhash, bssid, wl)
        #extract dict filename from url
        wl = wl.split('/')[-1]
        wl = wl.rsplit('.', 1)[0]
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

    key_temp = cap_temp.replace('.cap', '.key')

    #run cracker
    try:
        if tool.find('pyrit') != -1:
            cracker = '%s -i%s -o%s -b%s -r%s attack_passthrough' % (tool, wl, key_temp, bssid, cap_temp)
            subprocess.call(shlex.split(cracker))
        if tool.find('aircrack-ng') != -1:
            cracker = '%s -w%s -l%s -b%s %s' % (tool, wl, key_temp, bssid, cap_temp)
            subprocess.call(shlex.split(cracker))
        if tool.find('Hashcat-plus') != -1:
            subprocess.call(['aircrack-ng', '-Jwpa', cap_temp])
            if not os.path.exists('wpa.hccap'):
                print 'Could not create hccap file with aircrack-ng'
                exit(1)
            try:
                cracker = '%s -m2500 -o%s %s wpa.hccap %s' % (tool, key_temp, rule, wl)
                subprocess.check_call(shlex.split(cracker))
            except subprocess.CalledProcessError as ex:
                if ex.returncode == -2:
                    print 'Thermal watchdog barked'
                    sleepy()
                    continue
                if ex.returncode == -1:
                    print 'Internal error'
                    exit(1)
                if ex.returncode == 1:
                    print 'Exausted'
                if ex.returncode == 2:
                    print 'User abort'
                    exit(1)
                if ex.returncode not in [-2, -1, 1, 2]:
                    print 'Cracker %s died with code %i' % (tool, ex.returncode)
                    print 'Check you have CUDA/OpenCL support'
                    exit(1)
        if tool.find('hashcat-cli') != -1:
            subprocess.call(['aircrack-ng', '-Jwpa', cap_temp])
            if not os.path.exists('wpa.hccap'):
                print 'Could not create hccap file with aircrack-ng'
                exit(1)
            cracker = '%s -m2500 -o%s %s wpa.hccap %s' % (tool, key_temp, rule, wl)
            subprocess.call(shlex.split(cracker))
    except KeyboardInterrupt as ex:
        print 'Keyboard interrupt'
        if os.path.exists(key_temp):
            os.unlink(key_temp)
        exit(1)

    #if we have key, submit it
    if os.path.exists(key_temp):
        ktf = open(key_temp, 'r')
        key = ktf.readline()
        ktf.close()
        if tool.find('Hashcat-plus') != -1:
            key = key[key.find(':')+1:]
        if tool.find('hashcat-cli') != -1:
            key = key[key.find(':')+1:]
        key = key.rstrip('\n')
        print 'Key for capture hash '+nhash+' is: '+key
        while not put_work(nhash, key):
            print 'Couldn\'t submit key'
            sleepy()
        os.unlink(key_temp)
    else:
        print 'Key for capture hash '+nhash+' not found.'

    #cleanup
    if os.path.exists(cap_temp):
        os.unlink(cap_temp)
        os.unlink(cap_temp.replace('.cap', '.res'))
