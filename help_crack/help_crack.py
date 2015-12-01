#!/usr/bin/python2.7
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
import json
import base64
from distutils.version import StrictVersion

#some base variables
base_url = 'http://wpa-sec.stanev.org/'
help_crack = base_url + 'hc/help_crack.py'
help_crack_cl = base_url + 'hc/CHANGELOG'
get_work_url = base_url + '?get_work'
put_work_url = base_url + '?put_work'
res_file = 'help_crack.res'
net_file = 'help_crack.net'
key_file = 'help_crack.key'

#version
hc_ver = '0.8.6'

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
def get_url(url, options=None):
    try:
        response = urllib.urlopen(url, urllib.urlencode({'options': options}))
    except Exception as e:
        print 'Exception: %s' % e
        return None
    remote = response.read()
    response.close()

    return remote

#get md5 of current script, compare it with remote and initiate update
def check_version():
    remoteversion = get_url(help_crack+'.version')
    if not remoteversion:
        print 'Can\'t check for new version, continue...'
        return

    if StrictVersion(remoteversion) > StrictVersion(hc_ver):
        while True:
            user = raw_input('New version '+remoteversion+' of help_crack found. Update[y] or Show changelog[c]:')
            if user == 'c':
                print get_url(help_crack_cl)
                continue
            if user == 'y' or user == '':
                if download(help_crack, sys.argv[0]+'.new'):
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
def run_tool(xtool):
    if not isinstance(xtool, basestring):
        return False

    try:
        subprocess.check_call(shlex.split(xtool), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (subprocess.CalledProcessError, OSError):
        return False

    return True

#Hashcat always returns returncode 255
def run_hashcat(tool_hashcat):
    if not isinstance(tool_hashcat, basestring):
        return False

    try:
        acp = subprocess.Popen(tool_hashcat, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = acp.communicate()[0]
    except OSError:
        return False
    if output.find('hashcat') != -1:
        return True

    return False

#look for cracking tools, check for their capabilities, ask user
def check_tools():
    tools = []

    #search for general tools
    tl = ['pyrit', 'aircrack-ng']
    for xt in tl:
        t = which(xt)
        if t:
            tools.append(t)

    bits = platform.architecture()[0]
    if bits == '64bit':
        #this is for Hashcat
        tl = ['hashcat-cli64', 'hashcat-cliAVX', 'hashcat-cliXOP', 'hashcat-cli64.bin', 'hashcat-cliAVX.bin', 'hashcat-cliXOP.bin', 'hashcat-cli64.app']
        for xt in tl:
            t = which(xt)
            if t and run_hashcat(t):
                tools.append(t)
        #this is for oclHashcat
        tl = ['oclHashcat64', 'oclHashcat64.bin', 'cudaHashcat64', 'cudaHashcat64.bin']
        for xt in tl:
            t = which(xt)
            if t and run_tool(t+' -V'):
                tools.append(t)
    else:
        #this is for Hashcat
        tl = ['hashcat-cli32', 'hashcat-cli32.bin']
        for xt in tl:
            t = which(xt)
            if t and run_hashcat(t):
                tools.append(t)
        #this is for oclHashcat
        tl = ['oclHashcat32', 'oclHashcat32.bin', 'cudaHashcat32', 'cudaHashcat32.bin']
        for xt in tl:
            t = which(xt)
            if t and run_tool(t+' -V'):
                tools.append(t)

    if len(tools) == 0:
        print 'No aircrack-ng, pyrit, Hashcat or oclHashcat found'
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
        except (ValueError, IndexError):
            print 'Wrong index'

#get work
def get_work_wl(options):
    work = get_url(get_work_url+'='+hc_ver, options)
    try:
        xnetdata = json.loads(work)
        if len(xnetdata['mic']) != 32:
            return False
        if len(xnetdata['dhash']) != 32:
            return False
        if not valid_mac(xnetdata['bssid']):
            return False

        return xnetdata
    except (TypeError, ValueError, KeyError):
        if work == 'Version':
            print 'Please update help_crack, the interface has changed'
            exit(1)
        if work == 'No nets':
            print 'No suitable net found'
            return False

        print 'Server response error'

    return False

#prepare work based on netdata; returns dictname
def prepare_work(xnetdata, etype):
    if xnetdata is None:
        return False

    try:
        #write net
        try:
            gznet = base64.b64decode(xnetdata[etype])
            gzstream = StringIO.StringIO(gznet)
            fgz = gzip.GzipFile(fileobj=gzstream)
            fd = open(net_file, 'wb')
            fd.write(fgz.read())
            fd.close()
            fgz.close()
        except Exception as e:
            print 'Net data extraction failed'
            print 'Exception: %s' % e
            return False

        #check for dict and download it
        dictmd5 = ''
        extract = False
        gzdictname = xnetdata['dpath'].split('/')[-1]
        xdictname = gzdictname.rsplit('.', 1)[0]
        if os.path.exists(gzdictname):
            dictmd5 = md5file(gzdictname)
        if xnetdata['dhash'] != dictmd5:
            print 'Downloading ' + gzdictname
            if not download(xnetdata['dpath'], gzdictname):
                print 'Can\'t download dict ' + xnetdata['dpath']
                return False
            if md5file(gzdictname) != xnetdata['dhash']:
                print 'Dict downloaded but hash mismatch ' + xnetdata['dpath'] + 'dhash:' + xnetdata['dhash']

            extract = True

        if not os.path.exists(xdictname):
            extract = True

        if extract:
            print 'Extracting ' + gzdictname
            try:
                f = open(xdictname, 'wb')
                ftgz = gzip.open(gzdictname, 'rb')
                f.write(ftgz.read())
                f.close()
                ftgz.close()
            except Exception as e:
                print gzdictname +' extraction failed'
                print 'Exception: %s' % e
                return False

        return xdictname
    except TypeError as e:
        print 'Exception: %s' % e

    return False

#prepare chalenge files
def prepare_challenge(etype):
    xnetdata = {'cap':"""H4sICMX/HVQCA0d1ZXN0LmNhcAC7cnjTQiYGFgYY+P+fgSGTAQFOQnEDWA4EGCQsN7G9hZABDkLC\
                         dbpqQLkUBkEWBlb30tTiEkaOppbuaSoGHjnMjGysLAyMDAxajAz6jAwGEkAm/xomJhDJAmJB+AwM\
                         Riw8QhIJdzkZBCSYmL4AjbsrxzDBx1hOQgrkHizgrhRQ3oSNlw2bnAxDwCdGoNEBn0BWBXxiAbEg\
                         fISqmVDMwWXFyCKX4t3MgeKxm6tWMQNlO/qYmBlKmRi6GASg+pgcWX4zCD8+4HxdvbHeWIz1qojr\
                         9xUryrOaRPbGzTTV9JvLQCoQuysCCo9lAWozJoq7qJ4R/FM588BSFwyHMloxQhyH7FyF1SgOZeRC\
                         OPTsUeXVVntX39v7SjFY1D5CoJFZwOjn4tQzi43PHD9TfNyYkLtel7/+u/jBMXEvO651a0USwhnE\
                         DEQgEQYmWSBsHgYArgaqj0MCAAA=""",
                'hccap':"""H4sICN7CXVYCA2d1ZXN0Lm5ldABzL00tLmEgACQsN7G9ZZFL8W7mOHtUebXV3tX39r5SDBa1jxBo\
                           ZBYw+rk49cxi4zPHzxQfN3Zk+c0g/PiA83X1xnpjMdarIq7fV6woz2oS2Rs301TTby4TM0MpEyMX\
                           gwDUaCZCBjKQCsQMRBgZGPjXMIFJFgibh2GQgEqQn4H4dfnrv4sfHBP3suNat1YkIRwAu+stjIgB\
                           AAA=""",
                'bssid': '00:18:39:b2:06:ed',
                'mic': 'eb77ebfda3e0c6174a3e0aaead146057',
                'key': 'password1234',
                'dictname': 'challenge.txt'}
    try:
        #write net
        try:
            gznet = base64.b64decode(xnetdata[etype])
            gzstream = StringIO.StringIO(gznet)
            fgz = gzip.GzipFile(fileobj=gzstream)
            fd = open(net_file, 'wb')
            fd.write(fgz.read())
            fd.close()
            fgz.close()
        except Exception as e:
            print 'Net data extraction failed'
            print 'Exception: %s' % e
            return None

        #create dict
        try:
            f = open(xnetdata['dictname'], 'wb')
            f.write(xnetdata['key']+"\n")
            f.close()
        except Exception as e:
            print xnetdata['dictname'] + ' creation failed'
            print 'Exception: %s' % e
            return None

        return xnetdata
    except TypeError as e:
        print 'Exception: %s' % e

    return None

#return results to server
def put_work(mic, pwkey):
    data = urllib.urlencode({mic: pwkey})
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

#create resume file
def create_resume(xnetdata):
    with open(res_file, 'w') as outfile:
        json.dump(xnetdata, outfile)

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
    if os.path.exists(res_file):
        netdataf = open(res_file)
        try:
            xnetdata = json.load(netdataf)
            if len(xnetdata['mic']) != 32:
                raise ValueError
            print 'Session resume'
            return xnetdata
        except (TypeError, ValueError, KeyError):
            print 'Bad resume file contents'
            os.unlink(res_file)

    return None

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

#set format
if tool.find('ashcat') != -1:
    fformat = 'hccap'
else:
    fformat = 'cap'

challenge = False
resnetdata = resume_check()
netdata = None
while True:
    if challenge:
        if netdata is None:
            netdata = get_work_wl(json.JSONEncoder().encode({'format': fformat, 'tool': os.path.basename(tool)}))
            if netdata:
                create_resume(netdata)

        dictname = prepare_work(netdata, fformat)
        if not dictname:
            print 'Couldn\'t prepare data'
            netdata = None
            sleepy()
            continue

    else:
        netdata = prepare_challenge(fformat)
        if netdata is None:
            print 'Couldn\'t prepare challenge'
            exit(1)
        dictname = netdata['dictname']

    #check if we will use rules
    rule = ''
    if 'rule' in netdata:
        if tool.find('ashcat') != -1:
            if os.path.exists(netdata['rule']):
                rule = '-r'+netdata['rule']

    #run oclHashcat in performance tune mode
    performance = ''
    if tool.find('Hashcat') != -1:
        performance = '-w 3'

    #run cracker
    try:
        if tool.find('pyrit') != -1:
            cracker = '%s -i%s -o%s -b%s -r%s attack_passthrough' % (tool, dictname, key_file, netdata['bssid'], net_file)
            subprocess.call(shlex.split(cracker))
        if tool.find('aircrack-ng') != -1:
            cracker = '%s -w%s -l%s -b%s %s' % (tool, dictname, key_file, netdata['bssid'], net_file)
            subprocess.call(shlex.split(cracker))
        if tool.find('ashcat') != -1:
            try:
                cracker = '%s -m2500 --potfile-disable --outfile-format=2 %s -o%s %s %s %s' % (tool, performance, key_file, rule, net_file, dictname)
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
    except KeyboardInterrupt as ex:
        print 'Keyboard interrupt'
        if os.path.exists(key_file):
            os.unlink(key_file)
        exit(1)

    #if we have key, submit it
    if os.path.exists(key_file):
        ktf = open(key_file, 'r')
        key = ktf.readline()
        ktf.close()
        key = key.rstrip('\n')
        if challenge:
            print 'Key for capture mic '+netdata['mic']+' is: '+key.decode('utf8', 'ignore')
            while not put_work(netdata['mic'], key):
                print 'Couldn\'t submit key'
                sleepy()
        else:
            if netdata['key'] == key:
                print 'Challenge solved successfully!'
                challenge = True
                netdata = resnetdata

        os.unlink(key_file)
    else:
        if not challenge:
            print 'Challenge solving failed! Check if your cracker runs correctly.'
            exit(1)
        print 'Key for capture mic '+netdata['mic']+' not found.'

    #cleanup
    if os.path.exists(net_file):
        os.unlink(net_file)
    if resnetdata != netdata:
        if os.path.exists(res_file):
            os.unlink(res_file)
    netdata = None
