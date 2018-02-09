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
import json
import base64
from distutils.version import StrictVersion

#configuration
conf = {
    'base_url': 'http://wpa-sec.stanev.org/',
    'res_file': 'help_crack.res',
    'net_file': 'help_crack.net',
    'key_file': 'help_crack.key',
    'hc_ver': '0.8.8'
}
conf['help_crack'] = conf['base_url'] + 'hc/help_crack.py'
conf['help_crack_cl'] = conf['base_url'] + 'hc/CHANGELOG'
conf['get_work_url'] = conf['base_url'] + '?get_work'
conf['put_work_url'] = conf['base_url'] + '?put_work'


class HelpCrack(object):
    #decompression block size 64k
    blocksize = 1 << 16
    cc = None
    conf = None

    def __init__(self, c=None):
        self.conf = c

        #ANSI color codes, empty for win
        if os.name != 'nt':
            self.cc = {'HEADER':  '\033[95m',
                       'OKBLUE':  '\033[94m',
                       'OKGREEN': '\033[92m',
                       'WARNING': '\033[93m',
                       'FAIL':    '\033[91m',
                       'ENDC':    '\033[0m'}
        else:
            self.cc = {'HEADER':  '',
                       'OKBLUE':  '',
                       'OKGREEN': '',
                       'WARNING': '',
                       'FAIL':    '',
                       'ENDC':    ''}

    def sleepy(self):
        print self.cc['WARNING'] + 'Sleeping...' + self.cc['ENDC']
        time.sleep(222)

    #validate bssid/mac address
    @staticmethod
    def valid_mac(mac):
        if len(mac) != 17:
            return False
        if not re.match(r'^([a-f0-9]{2}\:?){6}$', mac):
            return False
        return True

    #get md5 from local file
    def md5file(self, filename):
        md5s = hashlib.md5()
        try:
            with open(filename, 'rb') as fd:
                for chunk in iter(lambda: fd.read(self.blocksize), ''):
                    md5s.update(chunk)
        except Exception as e:
            print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']
            return None

        return md5s.hexdigest()

    #download remote file
    def download(self, url, filename):
        try:
            urllib.urlretrieve(url, filename)
        except Exception as e:
            print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']
            return False

        return True

    #get remote content and return it in var
    def get_url(self, url, options=None):
        try:
            response = urllib.urlopen(url, urllib.urlencode({'options': options}))
        except Exception as e:
            print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']
            return None
        remote = response.read()
        response.close()

        return remote

    #compare version and initiate update
    def check_version(self):
        remoteversion = self.get_url(self.conf['help_crack']+'.version')
        if not remoteversion:
            print self.cc['WARNING'] + 'Can\'t check for new version, continue...' + self.cc['ENDC']
            return

        if StrictVersion(remoteversion) > StrictVersion(self.conf['hc_ver']):
            while True:
                user = raw_input(self.cc['HEADER'] + 'New version ' + remoteversion + ' of help_crack found. Update[y] or Show changelog[c]:' + self.cc['ENDC'])
                if user == 'c':
                    print self.get_url(self.conf['help_crack_cl'])
                    continue
                if user == 'y' or user == '':
                    if self.download(self.conf['help_crack'], sys.argv[0]+'.new'):
                        try:
                            os.rename(sys.argv[0]+'.new', sys.argv[0])
                            os.chmod(sys.argv[0], stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
                        except Exception as e:
                            print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']
                            #TODO: think of workaround locking on win32
                            if os.name == 'nt':
                                print self.cc['OKBLUE'] + 'You are running under win32, rename help_crack.py.new over help_crack.py' + self.cc['ENDC']
                        print self.cc['OKGREEN'] + 'help_crack updated, run again' + self.cc['ENDC']
                        exit(0)
                    else:
                        print self.cc['FAIL'] + 'help_crack update failed' + self.cc['ENDC']
                        return

                return

    #find executable in current dir or in PATH env var
    @staticmethod
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
    @staticmethod
    def run_hashcat(tool_hashcat):
        if not isinstance(tool_hashcat, basestring):
            return False

        try:
            acp = subprocess.Popen(shlex.split(tool_hashcat + ' -V'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = acp.communicate()[0]
        except OSError:
            return False

        output = re.sub(r'[^\d\.]', '', output)
        if StrictVersion(output) >= StrictVersion('4.0.1'):
            return True

        return False

    #look for cracking tools, check for their capabilities, ask user
    def check_tools(self):
        tools = []

        bits = platform.architecture()[0]
        if bits == '64bit':
            #this is for hashcat
            tl = ['hashcat64.bin', 'hashcat64']
            for xt in tl:
                t = self.which(xt)
                if t and self.run_hashcat(t):
                    tools.append(t)
        else:
            #this is for hashcat
            tl = ['hashcat32.bin', 'hashcat32']
            for xt in tl:
                t = self.which(xt)
                if t and self.run_hashcat(t):
                    tools.append(t)

        if not tools:
            print self.cc['FAIL'] + 'hashcat not found' + self.cc['ENDC']
            exit(1)
        if len(tools) == 1:
            return tools[0]

        print self.cc['HEADER'] + 'Choose the tool for cracking:' + self.cc['ENDC']
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
                print self.cc['WARNING'] + 'Wrong index' + self.cc['ENDC']

    #get work
    def get_work_wl(self, options):
        work = self.get_url(self.conf['get_work_url']+'='+self.conf['hc_ver'], options)
        try:
            xnetdata = json.loads(work)
            if len(xnetdata['hash']) != 32:
                return False
            if len(xnetdata['dhash']) != 32:
                return False
            if not self.valid_mac(xnetdata['bssid']):
                return False

            return xnetdata
        except (TypeError, ValueError, KeyError):
            if work == 'Version':
                print self.cc['FAIL'] + 'Please update help_crack, the interface has changed' + self.cc['ENDC']
                exit(1)
            if work == 'No nets':
                print self.cc['WARNING'] + 'No suitable net found' + self.cc['ENDC']
                return False

            print self.cc['WARNING'] + 'Server response error' + self.cc['ENDC']

        return False

    #prepare work based on netdata; returns dictname
    def prepare_work(self, xnetdata, etype):
        if xnetdata is None:
            return False

        try:
            #write net
            try:
                handshake = base64.b64decode(xnetdata[etype])
                with open(self.conf['net_file'], 'wb') as fd:
                    fd.write(handshake)
            except Exception as e:
                print self.cc['FAIL'] + 'Handshake write failed' + self.cc['ENDC']
                print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']
                return False

            #check for dict and download it
            dictmd5 = ''
            extract = False
            gzdictname = xnetdata['dpath'].split('/')[-1]
            xdictname = gzdictname.rsplit('.', 1)[0]
            if os.path.exists(gzdictname):
                dictmd5 = self.md5file(gzdictname)
            if xnetdata['dhash'] != dictmd5:
                print self.cc['OKBLUE'] + 'Downloading ' + gzdictname + self.cc['ENDC']
                if not self.download(xnetdata['dpath'], gzdictname):
                    print self.cc['FAIL'] + 'Can\'t download dict ' + xnetdata['dpath'] + self.cc['ENDC']
                    return False
                if self.md5file(gzdictname) != xnetdata['dhash']:
                    print self.cc['WARNING'] + 'Dict downloaded but hash mismatch dpath:{0} dhash:{1}'.format(xnetdata['dpath'], xnetdata['dhash']) + self.cc['ENDC']

                extract = True

            if not os.path.exists(xdictname):
                extract = True

            if extract:
                print self.cc['OKBLUE'] + 'Extracting ' + gzdictname + self.cc['ENDC']
                try:
                    with gzip.open(gzdictname, 'rb') as ftgz:
                        with open(xdictname, 'wb') as fd:
                            while True:
                                block = ftgz.read(self.blocksize)
                                if block == '':
                                    break
                                fd.write(block)
                except Exception as e:
                    print self.cc['FAIL'] + gzdictname + ' extraction failed' + self.cc['ENDC']
                    print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']

            return xdictname
        except TypeError as e:
            print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']

        return False

    #prepare chalenge files
    def prepare_challenge(self, etype):
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
                with open(self.conf['net_file'], 'wb') as fd:
                    fd.write(handshake)
            except Exception as e:
                print self.cc['FAIL'] + 'Handshake write failed' + self.cc['ENDC']
                print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']
                return None

            #create dict
            try:
                with open(xnetdata['dictname'], 'wb') as fd:
                    fd.write(xnetdata['key'] + "\n")
            except Exception as e:
                print self.cc['FAIL'] + xnetdata['dictname'] + ' creation failed' + self.cc['ENDC']
                print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']
                return None

            return xnetdata
        except TypeError as e:
            print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']

        return None

    #return results to server
    def put_work(self, handshakehash, pwkey):
        data = urllib.urlencode({handshakehash: pwkey})
        try:
            response = urllib.urlopen(self.conf['put_work_url'], data)
        except Exception as e:
            print self.cc['FAIL'] + 'Exception: {0}'.format(e) + self.cc['ENDC']
            return False

        remote = response.read()
        response.close()

        if remote != 'OK':
            return False

        return True

    #create resume file
    def create_resume(self, xnetdata):
        with open(self.conf['res_file'], 'w') as fd:
            json.dump(xnetdata, fd)

    #check for resume files
    def resume_check(self):
        if os.path.exists(self.conf['res_file']):
            with open(self.conf['res_file']) as fd:
                try:
                    xnetdata = json.load(fd)
                    if len(xnetdata['hash']) != 32:
                        raise ValueError
                    print self.cc['OKBLUE'] + 'Session resume' + self.cc['ENDC']
                    return xnetdata
                except (TypeError, ValueError, KeyError):
                    print self.cc['WARNING'] + 'Bad resume file contents' + self.cc['ENDC']
                    os.unlink(self.conf['res_file'])

        return None

    #entry point
    def run(self):
        self.check_version()
        tool = self.check_tools()

        #set format
        fformat = 'hccapx'

        challenge = False
        resnetdata = self.resume_check()
        netdata = None
        while True:
            if challenge:
                if netdata is None:
                    netdata = self.get_work_wl(json.JSONEncoder().encode({'format': fformat, 'tool': os.path.basename(tool)}))
                    if netdata:
                        self.create_resume(netdata)

                dictname = self.prepare_work(netdata, fformat)
                if not dictname:
                    print self.cc['WARNING'] + 'Couldn\'t prepare data' + self.cc['ENDC']
                    netdata = None
                    self.sleepy()
                    continue

            else:
                netdata = self.prepare_challenge(fformat)
                if netdata is None:
                    print self.cc['FAIL'] + 'Couldn\'t prepare challenge' + self.cc['ENDC']
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
                        cracker = '{0} -m2500 --nonce-error-corrections=128 --outfile-autohex-disable --potfile-disable --outfile-format=2 {1} -o{2} {3} {4} {5}'.format(tool, performance, self.conf['key_file'], rule, self.conf['net_file'], dictname)
                        subprocess.check_call(shlex.split(cracker))
                    except subprocess.CalledProcessError as ex:
                        if ex.returncode == -2:
                            print self.cc['WARNING'] + 'Thermal watchdog barked' + self.cc['ENDC']
                            self.sleepy()
                            continue
                        if ex.returncode == -1:
                            print self.cc['FAIL'] + 'Internal error' + self.cc['ENDC']
                            exit(1)
                        if ex.returncode == 1:
                            print self.cc['OKBLUE'] + 'Exausted' + self.cc['ENDC']
                        if ex.returncode == 2:
                            print self.cc['FAIL'] + 'User abort' + self.cc['ENDC']
                            exit(1)
                        if ex.returncode not in [-2, -1, 1, 2]:
                            print self.cc['FAIL'] + 'Cracker {0} died with code {1}'.format(tool, ex.returncode) + self.cc['ENDC']
                            print self.cc['FAIL'] + 'Check you have OpenCL support' + self.cc['ENDC']
                            exit(1)
            except KeyboardInterrupt as ex:
                print self.cc['OKBLUE'] + '\nKeyboard interrupt' + self.cc['ENDC']
                if os.path.exists(self.conf['key_file']):
                    os.unlink(self.conf['key_file'])
                exit(1)

            #if we have key, submit it
            if os.path.exists(self.conf['key_file']):
                with open(self.conf['key_file'], 'r') as fd:
                    key = fd.readline()
                key = key.rstrip('\n')
                if len(key) >= 8:
                    if challenge:
                        print self.cc['OKGREEN'] + 'Key for capture hash {0} is: {1}'.format(netdata['hash'], key.decode('utf8', 'ignore'))+self.cc['ENDC']
                        while not self.put_work(netdata['hash'], key):
                            print self.cc['WARNING'] + 'Couldn\'t submit key' + self.cc['ENDC']
                            self.sleepy()
                    else:
                        if netdata['key'] == key:
                            print self.cc['OKBLUE'] + 'Challenge solved successfully!' + self.cc['ENDC']
                            challenge = True
                            netdata = resnetdata

                os.unlink(self.conf['key_file'])
            else:
                if not challenge:
                    print self.cc['FAIL'] + 'Challenge solving failed! Check if your cracker runs correctly.' + self.cc['ENDC']
                    exit(1)
                print self.cc['OKBLUE'] + 'Key for capture hash {0} not found.'.format(netdata['hash']) + self.cc['ENDC']

            #cleanup
            if os.path.exists(self.conf['net_file']):
                os.unlink(self.conf['net_file'])
            if resnetdata != netdata:
                if os.path.exists(self.conf['res_file']):
                    os.unlink(self.conf['res_file'])
            netdata = None


# Execute
if __name__ == "__main__":
    print 'help_crack, distributed WPA cracker, v{0}\nsite: {1}'.format(conf['hc_ver'], conf['base_url'])

    if len(sys.argv) > 1:
        print 'Usage: {0} : download capture and wordlist then start cracking'.format(sys.argv[0])
        exit(1)

    hc = HelpCrack(conf)
    hc.run()
