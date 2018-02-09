#!/usr/bin/python2.7
# The source code is distributed under GPLv3+ license
# author: Alex Stanev, alex at stanev dot org
# web: http://wpa-sec.stanev.org

from __future__ import print_function
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
    conf = None

    def __init__(self, c=None):
        self.conf = c

    #pretty print
    @staticmethod
    def pprint(mess, code='HEADER'):
        if os.name == 'nt':
            print(mess)
        else:
            cc = {'HEADER':  '\033[95m',
                  'OKBLUE':  '\033[94m',
                  'OKGREEN': '\033[92m',
                  'WARNING': '\033[93m',
                  'FAIL':    '\033[91m',
                  'ENDC':    '\033[0m'}
            print(cc[code] + mess + cc['ENDC'])

    def sleepy(self):
        self.pprint('Sleeping...', 'WARNING')
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
        except OSError as e:
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            return None

        return md5s.hexdigest()

    #download remote file
    def download(self, url, filename):
        try:
            urllib.urlretrieve(url, filename)
        except IOError as e:
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            return False

        return True

    #get remote content and return it in var
    def get_url(self, url, options=None):
        try:
            response = urllib.urlopen(url, urllib.urlencode({'options': options}))
        except IOError as e:
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            return None
        remote = response.read()
        response.close()

        return remote

    #compare version and initiate update
    def check_version(self):
        remoteversion = self.get_url(self.conf['help_crack']+'.version')
        if not remoteversion:
            self.pprint('Can\'t check for new version, continue...', 'WARNING')
            return

        if StrictVersion(remoteversion) > StrictVersion(self.conf['hc_ver']):
            while True:
                self.pprint('New version ' + remoteversion + ' of help_crack found.')
                user = raw_input('Update[y] or Show changelog[c]:')
                if user == 'c':
                    self.pprint(self.get_url(self.conf['help_crack_cl']))
                    continue
                if user == 'y' or user == '':
                    if self.download(self.conf['help_crack'], sys.argv[0]+'.new'):
                        try:
                            os.rename(sys.argv[0]+'.new', sys.argv[0])
                            os.chmod(sys.argv[0], stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
                        except OSError as e:
                            self.pprint('Exception: {0}'.format(e), 'FAIL')
                            #TODO: think of workaround locking on win32
                            if os.name == 'nt':
                                self.pprint('You are running under win32, rename help_crack.py.new over help_crack.py', 'OKBLUE')
                        self.pprint('help_crack updated, run again', 'OKGREEN')
                        exit(0)
                    else:
                        self.pprint('help_crack update failed', 'FAIL')
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
            self.pprint('hashcat not found', 'FAIL')
            exit(1)
        if len(tools) == 1:
            return tools[0]

        self.pprint('Choose the tool for cracking:')
        for index, ttool in enumerate(tools):
            print('{0}: {1}'.format(index, ttool))
        print('9: Quit')
        while 1:
            user = raw_input('Index:')
            if user == '9':
                exit(0)
            try:
                return tools[int(user)]
            except (ValueError, IndexError):
                self.pprint('Wrong index', 'WARNING')

    #get work
    def get_work_wl(self, options):
        work = self.get_url(self.conf['get_work_url']+'='+self.conf['hc_ver'], options)
        try:
            netdata = json.loads(work)
            if len(netdata['hash']) != 32:
                return False
            if len(netdata['dhash']) != 32:
                return False
            if not self.valid_mac(netdata['bssid']):
                return False

            return netdata
        except (TypeError, ValueError, KeyError):
            if work == 'Version':
                self.pprint('Please update help_crack, the API has changed', 'FAIL')
                exit(1)
            if work == 'No nets':
                self.pprint('No suitable net found', 'WARNING')
                return False

            self.pprint('Server response error', 'WARNING')

        return False

    #prepare work based on netdata; returns dictname
    def prepare_work(self, netdata, etype):
        if netdata is None:
            return False

        try:
            #write net
            try:
                handshake = base64.b64decode(netdata[etype])
                with open(self.conf['net_file'], 'wb') as fd:
                    fd.write(handshake)
            except OSError as e:
                self.pprint('Handshake write failed', 'FAIL')
                self.pprint('Exception: {0}'.format(e), 'FAIL')
                return False

            #check for dict and download it
            dictmd5 = ''
            extract = False
            gzdictname = netdata['dpath'].split('/')[-1]
            dictname = gzdictname.rsplit('.', 1)[0]
            if os.path.exists(gzdictname):
                dictmd5 = self.md5file(gzdictname)
            if netdata['dhash'] != dictmd5:
                self.pprint('Downloading ' + gzdictname, 'OKBLUE')
                if not self.download(netdata['dpath'], gzdictname):
                    self.pprint('Can\'t download dict ' + netdata['dpath'], 'FAIL')
                    return False
                if self.md5file(gzdictname) != netdata['dhash']:
                    self.pprint('Dict downloaded but hash mismatch dpath:{0} dhash:{1}'.format(netdata['dpath'], netdata['dhash']), 'WARNING')

                extract = True

            if not os.path.exists(dictname):
                extract = True

            if extract:
                self.pprint('Extracting ' + gzdictname, 'OKBLUE')
                try:
                    with gzip.open(gzdictname, 'rb') as ftgz:
                        with open(dictname, 'wb') as fd:
                            while True:
                                block = ftgz.read(self.blocksize)
                                if block == '':
                                    break
                                fd.write(block)
                except OSError as e:
                    self.pprint(gzdictname + ' extraction failed', 'FAIL')
                    self.pprint('Exception: {0}'.format(e), 'FAIL')

            return dictname
        except TypeError as e:
            self.pprint('Exception: {0}'.format(e), 'FAIL')

        return False

    #prepare chalenge files
    def prepare_challenge(self, etype):
        netdata = {'hccapx': """SENQWAQAAAAABWRsaW5rAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiaaYe8l4TWktCODLsTs\
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
                handshake = base64.b64decode(netdata[etype])
                with open(self.conf['net_file'], 'wb') as fd:
                    fd.write(handshake)
            except OSError as e:
                self.pprint('Handshake write failed', 'FAIL')
                self.pprint('Exception: {0}'.format(e), 'FAIL')
                exit(1)

            #create dict
            try:
                with open(netdata['dictname'], 'wb') as fd:
                    fd.write(netdata['key'] + "\n")
            except OSError as e:
                self.pprint(netdata['dictname'] + ' creation failed', 'FAIL')
                self.pprint('Exception: {0}'.format(e), 'FAIL')
                exit(1)

            return netdata
        except TypeError as e:
            self.pprint('Couldn\'t prepare challenge', 'FAIL')
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            exit(1)

    #return results to server
    def put_work(self, handshakehash, pwkey):
        data = urllib.urlencode({handshakehash: pwkey})
        try:
            response = urllib.urlopen(self.conf['put_work_url'], data)
        except IOError as e:
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            return False

        response.close()

        return True

    #create resume file
    def create_resume(self, netdata):
        with open(self.conf['res_file'], 'w') as fd:
            json.dump(netdata, fd)

    #check for resume files
    def resume_check(self):
        if os.path.exists(self.conf['res_file']):
            with open(self.conf['res_file']) as fd:
                try:
                    netdata = json.load(fd)
                    if len(netdata['hash']) != 32:
                        raise ValueError
                    self.pprint('Session resume', 'OKBLUE')
                    return netdata
                except (TypeError, ValueError, KeyError):
                    self.pprint('Bad resume file contents', 'WARNING')
                    os.unlink(self.conf['res_file'])

        return None

    #run externel cracker process
    def run_cracker(self, tool, dictname, performance='', rule=''):
        while True:
            try:
                if tool.find('ashcat'):
                    try:
                        cracker = '{0} -m2500 --nonce-error-corrections=128 --outfile-autohex-disable --potfile-disable --outfile-format=2 {1} -o{2} {3} {4} {5}'.format(tool, performance, self.conf['key_file'], rule, self.conf['net_file'], dictname)
                        subprocess.check_call(shlex.split(cracker))
                    except subprocess.CalledProcessError as ex:
                        if ex.returncode == -2:
                            self.pprint('Thermal watchdog barked', 'WARNING')
                            self.sleepy()
                            continue
                        if ex.returncode == -1:
                            self.pprint('Internal error', 'FAIL')
                            exit(1)
                        if ex.returncode == 1:
                            self.pprint('Exausted', 'OKBLUE')
                            return ex.returncode
                        if ex.returncode == 2:
                            self.pprint('User abort', 'FAIL')
                            exit(1)
                        if ex.returncode not in [-2, -1, 1, 2]:
                            self.pprint('Cracker {0} died with code {1}'.format(tool, ex.returncode), 'FAIL')
                            self.pprint('Check you have OpenCL support', 'FAIL')
                            exit(1)
            except KeyboardInterrupt as ex:
                self.pprint('\nKeyboard interrupt', 'OKBLUE')
                if os.path.exists(self.conf['key_file']):
                    os.unlink(self.conf['key_file'])
                exit(1)

            return 0

    #read key from file
    def get_key(self):
        try:
            if os.path.exists(self.conf['key_file']):
                with open(self.conf['key_file'], 'r') as fd:
                    key = fd.readline()
                key = key.rstrip('\n')
                if len(key) >= 8:
                    os.unlink(self.conf['key_file'])
                    return key
        except IOError as e:
            self.pprint('Couldn\'t read key', 'FAIL')
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            exit(1)

        return None

    #entry point
    def run(self):
        self.check_version()
        tool = self.check_tools()

        #set format
        fformat = 'hccapx'

        #run hashcat in performance tune mode
        performance = ''
        if tool.find('ashcat'):
            performance = '-w 3'

        #challenge the cracker
        self.pprint('Challenge cracker for correct results', 'OKBLUE')
        netdata = self.prepare_challenge(fformat)
        rc = self.run_cracker(tool, netdata['dictname'], performance)
        key = self.get_key()
        if rc != 0 or key != netdata['key']:
            self.pprint('Challenge solving failed! Check if your cracker runs correctly.', 'FAIL')
            exit(1)

        netdata = self.resume_check()

        while True:
            if netdata is None:
                netdata = self.get_work_wl(json.JSONEncoder().encode({'format': fformat, 'tool': os.path.basename(tool)}))
                if netdata:
                    self.create_resume(netdata)

            dictname = self.prepare_work(netdata, fformat)
            if not dictname:
                self.pprint('Couldn\'t prepare data', 'WARNING')
                netdata = None
                self.sleepy()
                continue

            #check if we will use rules
            rule = ''
            if 'rule' in netdata and tool.find('ashcat') and os.path.exists(netdata['rule']):
                rule = '-r' + netdata['rule']

            rc = self.run_cracker(tool, dictname, performance, rule)
            if rc == 0:
                key = self.get_key()
                self.pprint('Key for capture hash {0} is: {1}'.format(netdata['hash'], key.decode('utf8', 'ignore')), 'OKGREEN')
                while not self.put_work(netdata['hash'], key):
                    self.pprint('Couldn\'t submit key', 'WARNING')
                    self.sleepy()

            #cleanup
            if os.path.exists(self.conf['net_file']):
                os.unlink(self.conf['net_file'])
            if os.path.exists(self.conf['res_file']):
                os.unlink(self.conf['res_file'])
            netdata = None


# Execute
if __name__ == "__main__":
    print('help_crack, distributed WPA cracker, v{0}\nsite: {1}'.format(conf['hc_ver'], conf['base_url']))

    if len(sys.argv) > 1:
        print('Usage: {0} : download capture and wordlist then start cracking'.format(sys.argv[0]))
        exit(1)

    hc = HelpCrack(conf)
    hc.run()
