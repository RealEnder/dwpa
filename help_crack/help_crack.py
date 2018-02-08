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
hc_ver = '0.8.8'

#decompression block size 64k
blocksize = 1 << 16

#ANSI color codes
#empty for win
if os.name != 'nt':
    cc = {'HEADER':  '\033[95m',
          'OKBLUE':  '\033[94m',
          'OKGREEN': '\033[92m',
          'WARNING': '\033[93m',
          'FAIL':    '\033[91m',
          'ENDC':    '\033[0m'}
else:
    cc = {'HEADER':  '',
          'OKBLUE':  '',
          'OKGREEN': '',
          'WARNING': '',
          'FAIL':    '',
          'ENDC':    ''}

def sleepy():
    print cc['WARNING'] + 'Sleeping...' + cc['ENDC']
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
            for chunk in iter(lambda: f.read(blocksize), ''):
                md5s.update(chunk)
    except Exception as e:
        print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']
        return None

    return md5s.hexdigest()

#download remote file
def download(url, filename):
    try:
        urllib.urlretrieve(url, filename)
    except Exception as e:
        print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']
        return False

    return True

#get remote content and return it in var
def get_url(url, options=None):
    try:
        response = urllib.urlopen(url, urllib.urlencode({'options': options}))
    except Exception as e:
        print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']
        return None
    remote = response.read()
    response.close()

    return remote

#get md5 of current script, compare it with remote and initiate update
def check_version():
    remoteversion = get_url(help_crack+'.version')
    if not remoteversion:
        print cc['WARNING'] + 'Can\'t check for new version, continue...' + cc['ENDC']
        return

    if StrictVersion(remoteversion) > StrictVersion(hc_ver):
        while True:
            user = raw_input(cc['HEADER'] + 'New version ' + remoteversion + ' of help_crack found. Update[y] or Show changelog[c]:' + cc['ENDC'])
            if user == 'c':
                print get_url(help_crack_cl)
                continue
            if user == 'y' or user == '':
                if download(help_crack, sys.argv[0]+'.new'):
                    try:
                        os.rename(sys.argv[0]+'.new', sys.argv[0])
                        os.chmod(sys.argv[0], stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
                    except Exception as e:
                        print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']
                        #TODO: think of workaround locking on win32
                        if os.name == 'nt':
                            print cc['OKBLUE'] + 'You are running under win32, rename help_crack.py.new over help_crack.py' + cc['ENDC']
                    print cc['OKGREEN'] + 'help_crack updated, run again' + cc['ENDC']
                    exit(0)
                else:
                    print cc['FAIL'] + 'help_crack update failed' + cc['ENDC']
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

#check hashcat version
def run_hashcat(tool_hashcat):
    if not isinstance(tool_hashcat, basestring):
        return False

    try:
        acp = subprocess.Popen(shlex.split(tool_hashcat + ' -V'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = acp.communicate()[0]
    except OSError:
        return False

    output = re.sub('[^\d\.]', '', output)
    if StrictVersion(output) >= StrictVersion('4.0.1'):
        return True

    return False

#look for cracking tools, check for their capabilities, ask user
def check_tools():
    tools = []

    bits = platform.architecture()[0]
    if bits == '64bit':
        #this is for hashcat
        tl = ['hashcat64.bin', 'hashcat64']
        for xt in tl:
            t = which(xt)
            if t and run_hashcat(t):
                tools.append(t)
    else:
        #this is for hashcat
        tl = ['hashcat32.bin', 'hashcat32']
        for xt in tl:
            t = which(xt)
            if t and run_hashcat(t):
                tools.append(t)

    if len(tools) == 0:
        print cc['FAIL'] + 'hashcat not found' + cc['ENDC']
        exit(1)
    if len(tools) == 1:
        return tools[0]

    print cc['HEADER'] + 'Choose the tool for cracking:' + cc['ENDC']
    for index, ttool in enumerate(tools):
        print '{0}: {1}'.format(index, ttool)
    print '9: Quit'
    while 1:
        user = raw_input('Index:')
        if user == '9':
            exit(0)
        try:
            return tools[int(user)]
        except (ValueError, IndexError):
            print cc['WARNING'] + 'Wrong index' + cc['ENDC']

#get work
def get_work_wl(options):
    work = get_url(get_work_url+'='+hc_ver, options)
    try:
        xnetdata = json.loads(work)
        if len(xnetdata['hash']) != 32:
            return False
        if len(xnetdata['dhash']) != 32:
            return False
        if not valid_mac(xnetdata['bssid']):
            return False

        return xnetdata
    except (TypeError, ValueError, KeyError):
        if work == 'Version':
            print cc['FAIL'] + 'Please update help_crack, the interface has changed' + cc['ENDC']
            exit(1)
        if work == 'No nets':
            print cc['WARNING'] + 'No suitable net found' + cc['ENDC']
            return False

        print cc['WARNING'] + 'Server response error' + cc['ENDC']

    return False

#prepare work based on netdata; returns dictname
def prepare_work(xnetdata, etype):
    if xnetdata is None:
        return False

    try:
        #write net
        try:
            handshake = base64.b64decode(xnetdata[etype])
            fd = open(net_file, 'wb')
            fd.write(handshake)
            fd.close()
        except Exception as e:
            print cc['FAIL'] + 'Handshake write failed' + cc['ENDC']
            print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']
            return False

        #check for dict and download it
        dictmd5 = ''
        extract = False
        gzdictname = xnetdata['dpath'].split('/')[-1]
        xdictname = gzdictname.rsplit('.', 1)[0]
        if os.path.exists(gzdictname):
            dictmd5 = md5file(gzdictname)
        if xnetdata['dhash'] != dictmd5:
            print cc['OKBLUE'] + 'Downloading ' + gzdictname + cc['ENDC']
            if not download(xnetdata['dpath'], gzdictname):
                print cc['FAIL'] + 'Can\'t download dict ' + xnetdata['dpath'] + cc['ENDC']
                return False
            if md5file(gzdictname) != xnetdata['dhash']:
                print cc['WARNING'] + 'Dict downloaded but hash mismatch dpath:{0} dhash:{1}'.format(xnetdata['dpath'], xnetdata['dhash']) + cc['ENDC']

            extract = True

        if not os.path.exists(xdictname):
            extract = True

        if extract:
            print cc['OKBLUE'] + 'Extracting ' + gzdictname + cc['ENDC']
            try:
                with gzip.open(gzdictname, 'rb') as ftgz:
                    f = open(xdictname, 'wb')
                    while True:
                        block = ftgz.read(blocksize)
                        if block == '':
                            break
                        f.write(block)
                f.close()
                ftgz.close()
            except Exception as e:
                print cc['FAIL'] + gzdictname + ' extraction failed' + cc['ENDC']
                print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']

        return xdictname
    except TypeError as e:
        print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']

    return False

#prepare chalenge files
def prepare_challenge(etype):
    xnetdata = {'hccapx': """SENQWAQAAAAABWRsaW5rAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiaaYe8l4TWktCODLsTs\
                             x/QcfuXi8tDb0kmj6c7GztM2D7o/rpukqm7Gx2EFeW/2taIJ0YeCygAmxy5JAGRbH2hKJWbiEmbx\
                             I6vDhsxXb1k+bcXjgjoy+9Svkp9RewABAwB3AgEKAAAAAAAAAAAAAGRbH2hKJWbiEmbxI6vDhsxX\
                             b1k+bcXjgjoy+9Svkp9RAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                             AAAAAAAAABgwFgEAAA+sAgEAAA+sBAEAAA+sAjwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""",
                'bssid': '1c:7e:e5:e2:f2:d0',
                'hash': '0747af15ffbd5ce545c862dd1e36d727',
                'key': 'aaaa1234',
                'dictname': 'challenge.txt'}
    try:
        #write net
        try:
            handshake = base64.b64decode(xnetdata[etype])
            fd = open(net_file, 'wb')
            fd.write(handshake)
            fd.close()
        except Exception as e:
            print cc['FAIL'] + 'Handshake write failed' + cc['ENDC']
            print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']
            return None

        #create dict
        try:
            fd = open(xnetdata['dictname'], 'wb')
            fd.write(xnetdata['key'] + "\n")
            fd.close()
        except Exception as e:
            print cc['FAIL'] + xnetdata['dictname'] + ' creation failed' + cc['ENDC']
            print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']
            return None

        return xnetdata
    except TypeError as e:
        print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']

    return None

#return results to server
def put_work(handshakehash, pwkey):
    data = urllib.urlencode({handshakehash: pwkey})
    try:
        response = urllib.urlopen(put_work_url, data)
    except Exception as e:
        print cc['FAIL'] + 'Exception: {0}'.format(e) + cc['ENDC']
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

#check for resume files
def resume_check():
    if os.path.exists(res_file):
        netdataf = open(res_file)
        try:
            xnetdata = json.load(netdataf)
            if len(xnetdata['hash']) != 32:
                raise ValueError
            print cc['OKBLUE'] + 'Session resume' + cc['ENDC']
            return xnetdata
        except (TypeError, ValueError, KeyError):
            print cc['WARNING'] + 'Bad resume file contents' + cc['ENDC']
            os.unlink(res_file)

    return None

print cc['HEADER'] + 'help_crack, distributed WPA cracker, v{0}\nsite: {1}'.format(hc_ver, base_url) + cc['ENDC']

wordlist = ''
if len(sys.argv) > 1:
    print cc['HEADER'] + 'Usage: ./help_crack.py : download capture and wordlist then start cracking' + cc['ENDC']
    exit(1)

check_version()
tool = check_tools()

#set format
fformat = 'hccapx'

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
            print cc['WARNING'] + 'Couldn\'t prepare data' + cc['ENDC']
            netdata = None
            sleepy()
            continue

    else:
        netdata = prepare_challenge(fformat)
        if netdata is None:
            print cc['FAIL'] + 'Couldn\'t prepare challenge' + cc['ENDC']
            exit(1)
        dictname = netdata['dictname']

    #check if we will use rules
    rule = ''
    if 'rule' in netdata:
        if tool.find('ashcat') != -1:
            if os.path.exists(netdata['rule']):
                rule = '-r' + netdata['rule']

    #run oclHashcat in performance tune mode
    performance = ''
    if tool.find('ashcat') != -1:
        performance = '-w 3'

    #run cracker
    try:
        if tool.find('ashcat') != -1:
            try:
                cracker = '{0} -m2500 --nonce-error-corrections=128 --outfile-autohex-disable --potfile-disable --outfile-format=2 {1} -o{2} {3} {4} {5}'.format(tool, performance, key_file, rule, net_file, dictname)
                subprocess.check_call(shlex.split(cracker))
            except subprocess.CalledProcessError as ex:
                if ex.returncode == -2:
                    print cc['WARNING'] + 'Thermal watchdog barked' + cc['ENDC']
                    sleepy()
                    continue
                if ex.returncode == -1:
                    print cc['FAIL'] + 'Internal error' + cc['ENDC']
                    exit(1)
                if ex.returncode == 1:
                    print cc['OKBLUE'] + 'Exausted' + cc['ENDC']
                if ex.returncode == 2:
                    print cc['FAIL'] + 'User abort' + cc['ENDC']
                    exit(1)
                if ex.returncode not in [-2, -1, 1, 2]:
                    print cc['FAIL'] + 'Cracker {0} died with code {1}'.format(tool, ex.returncode) + cc['ENDC']
                    print cc['FAIL'] + 'Check you have OpenCL support' + cc['ENDC']
                    exit(1)
    except KeyboardInterrupt as ex:
        print cc['OKBLUE'] + '\nKeyboard interrupt' + cc['ENDC']
        if os.path.exists(key_file):
            os.unlink(key_file)
        exit(1)

    #if we have key, submit it
    if os.path.exists(key_file):
        ktf = open(key_file, 'r')
        key = ktf.readline()
        ktf.close()
        key = key.rstrip('\n')
        if len(key) >= 8:
            if challenge:
                print cc['OKGREEN'] + 'Key for capture hash {0} is: {1}'.format(netdata['hash'], key.decode('utf8', 'ignore'))+cc['ENDC']
                while not put_work(netdata['hash'], key):
                    print cc['WARNING'] + 'Couldn\'t submit key' + cc['ENDC']
                    sleepy()
            else:
                if netdata['key'] == key:
                    print cc['OKBLUE'] + 'Challenge solved successfully!' + cc['ENDC']
                    challenge = True
                    netdata = resnetdata

        os.unlink(key_file)
    else:
        if not challenge:
            print cc['FAIL'] + 'Challenge solving failed! Check if your cracker runs correctly.' + cc['ENDC']
            exit(1)
        print cc['OKBLUE'] + 'Key for capture hash {0} not found.'.format(netdata['hash']) + cc['ENDC']

    #cleanup
    if os.path.exists(net_file):
        os.unlink(net_file)
    if resnetdata != netdata:
        if os.path.exists(res_file):
            os.unlink(res_file)
    netdata = None

