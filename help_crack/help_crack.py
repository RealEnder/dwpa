#!/usr/bin/env python
'''Clientside part of dwpa distributed cracker
The source code is distributed under GPLv3+ license
author: Alex Stanev, alex at stanev dot org
web: http://wpa-sec.stanev.org'''

from __future__ import print_function
import sys
import os
import platform
import subprocess
import shlex
import stat
import hashlib
import zlib
import gzip
import re
import time
import json
import base64
import struct
from distutils.version import StrictVersion
from functools import partial
from binascii import hexlify

try:
    from urllib import urlretrieve
    from urllib import urlopen
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
    from urllib.request import urlopen, urlretrieve

try:
    from string import maketrans
except ImportError:
    maketrans = bytearray.maketrans

try:
    userinput = raw_input
except NameError:
    userinput = input

#configuration
conf = {
    'base_url': 'http://wpa-sec.stanev.org/',
    'res_file': 'help_crack.res',
    'net_file': 'help_crack.net',
    'key_file': 'help_crack.key',
    'hc_ver': '0.9.0'
}
conf['help_crack'] = conf['base_url'] + 'hc/help_crack.py'
conf['help_crack_cl'] = conf['base_url'] + 'hc/CHANGELOG'
conf['get_work_url'] = conf['base_url'] + '?get_work'
conf['put_work_url'] = conf['base_url'] + '?put_work'


class HelpCrack(object):
    '''Main helpcrack class'''
    #decompression block size 64k
    blocksize = 1 << 16
    conf = None

    def __init__(self, c=None):
        self.conf = c

    @staticmethod
    def pprint(mess, code='HEADER'):
        '''pretty print'''
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

    def sleepy(self, sec=222):
        '''wait for calm down'''
        self.pprint('Sleeping...', 'WARNING')
        time.sleep(sec)

    @staticmethod
    def valid_mac(mac):
        '''validate bssid/mac address'''
        if len(mac) != 17:
            return False
        if not re.match(r'^([a-f0-9]{2}\:?){6}$', mac):
            return False
        return True

    def md5file(self, filename):
        '''compute md5 over local file'''
        md5 = hashlib.md5()
        try:
            with open(filename, 'rb') as fd:
                for chunk in iter(partial(fd.read, self.blocksize), b''):
                    if not chunk:
                        break
                    md5.update(chunk)
        except OSError as e:
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            return None

        return md5.hexdigest()

    def download(self, url, filename):
        '''download remote file'''
        try:
            urlretrieve(url, filename)
        except IOError as e:
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            return False

        return True

    def get_url(self, url, options=None):
        '''get remote content and return it in var'''
        try:
            data = urlencode({'options': options}).encode()
            response = urlopen(url, data)
        #URLError
        except IOError as e:
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            return None
        remote = response.read()
        response.close()

        return remote.decode()

    def check_version(self):
        '''compare version and initiate update'''
        remoteversion = self.get_url(self.conf['help_crack']+'.version')
        if not remoteversion:
            self.pprint('Can\'t check for new version, continue...', 'WARNING')
            return

        if StrictVersion(remoteversion) > StrictVersion(self.conf['hc_ver']):
            while True:
                self.pprint('New version ' + remoteversion + ' of help_crack found.')
                user = userinput('Update[y] or Show changelog[c]:')
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

    @staticmethod
    def which(program):
        '''find executable in current dir or in PATH env var'''
        def is_exe(fpath):
            '''check if file exists and is executable'''
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

    @staticmethod
    def run_hashcat(tool_hashcat):
        '''check hashcat version'''
        try:
            acp = subprocess.Popen(shlex.split(tool_hashcat + ' -V'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = acp.communicate()[0]
        except OSError:
            return False

        output = re.sub(r'[^\d\.]', '', output.decode())
        if StrictVersion(output) >= StrictVersion('4.0.1'):
            return True

        return False

    @staticmethod
    def run_jtr(tool_jtr):
        '''check JtR capabilities'''
        try:
            acp = subprocess.Popen(shlex.split(tool_jtr), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = acp.communicate()[0]
        except OSError:
            return False

        if output.find(b'PASS') != -1:
            return True

        return False

    def check_tools(self):
        '''look for cracking tools, check for their capabilities, ask user'''
        tools = []

        #hashcat
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

        #John the Ripper
        t = self.which('john')
        if t:
            if self.run_jtr(t + ' --format=wpapsk --test=0'):
                tools.append(t + ' --format=wpapsk')
            if self.run_jtr(t + ' --format=wpapsk-opencl --test=0'):
                tools.append(t + ' --format=wpapsk-opencl')
            if self.run_jtr(t + ' --format=wpapsk-cuda --test=0'):
                tools.append(t + ' --format=wpapsk-cuda')

        if not tools:
            self.pprint('hashcat or john not found', 'FAIL')
            exit(1)
        if len(tools) == 1:
            return tools[0]

        self.pprint('Choose the tool for cracking:')
        for index, ttool in enumerate(tools):
            print('{0}: {1}'.format(index, ttool))
        print('9: Quit')
        while 1:
            user = userinput('Index:')
            if user == '9':
                exit(0)
            try:
                return tools[int(user)]
            except (ValueError, IndexError):
                self.pprint('Wrong index', 'WARNING')

    def get_work_wl(self, options):
        '''pull handshake and dictionary'''
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

    def hccapx2john(self, hccapx):
        '''convert hccapx struct to JtR $WPAPSK$ and implement nonce correction
            hccap:  https://hashcat.net/wiki/doku.php?id=hccap
            hccapx: https://hashcat.net/wiki/doku.php?id=hccapx
            JtR:    $WPAPSK$essid#b64encoded hccap
        '''

        def pack_jtr(hccap, hccapx, essid, corr='', nc=0, endian=''):
            '''prepare handshake in JtR format'''
            jtr = '{0}:$WPAPSK${0}#{1}:{2}:{3}:{3}::{4}:{5}:/dev/null\n'

            #cut essid part and stuff correction, if passed
            if corr == '':
                newhccap = hccap[36:]
            else:
                newhccap = hccap[36:108] + corr + hccap[112:]

            mac_sta = hexlify(hccap[42:47])
            mac_ap = hexlify(hccap[36:42])
            keyver = struct.unpack('<L', hccap[372:376])[0]
            if keyver == 1:
                keyver = 'WPA'
            elif keyver == 2:
                keyver = 'WPA2'
            elif keyver >= 3:
                keyver = 'WPA CMAC'

            #message_pair check
            if ord(hccapx[8:9]) & 0x80 > 1:
                ver = 'verified'
            else:
                ver = 'not verified'

            #nc fuzzing info
            if nc != 0:
                ver += ', fuzz {0} {1}'.format(nc, endian)

            #prepare translation to base64 alphabet used by JtR
            sta_ab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.encode()
            jtr_ab = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.encode()
            encode_trans = maketrans(sta_ab, jtr_ab)

            #workaround python 2/3 shit
            try:
                essid = bytes(essid).decode()
            except UnicodeDecodeError:
                essid = bytes(essid)

            return jtr.format(essid,
                              base64.b64encode(newhccap).translate(encode_trans)[:-1].decode(),
                              mac_sta.decode(),
                              mac_ap.decode(),
                              keyver,
                              ver)

        #essid
        hccap = hccapx[10:42] + b'\x00\x00\x00\x00'
        #mac1 = mac_ap
        hccap += hccapx[59:65]
        #mac2 = mac_sta
        hccap += hccapx[97:103]
        #snonce = nonce_sta
        hccap += hccapx[103:135]
        #anonce = nonce_ap
        hccap += hccapx[65:97]
        #eapol
        hccap += hccapx[137:393]
        #eapol_size = eapol_len
        hccap += hccapx[135:137] + b'\x00\x00'
        #keyver
        hccap += hccapx[42:43] + b'\x00\x00\x00'
        #keymic
        hccap += hccapx[43:59]

        #get and eventually fixup essid_len
        essid_len = ord(hccapx[9:10])
        if essid_len > 32:
            essid_len = 32
        #get essid
        essid = hccapx[10:10+essid_len]

        #exact handshake
        hccaps = pack_jtr(hccap, hccapx, essid)

        #get last nonce_ap 4 bytes for correction
        corrle = struct.unpack('<L', hccapx[93:97])[0]
        corrbe = struct.unpack('>L', hccapx[93:97])[0]

        #prepare nonce correction
        for i in range(1, 128):
            #LE+
            if corrle+i <= 4294967295:
                newcorr = struct.pack('<L', corrle+i)
                hccaps += pack_jtr(hccap, hccapx, essid, newcorr, i, 'LE')
            #LE-
            if corrle-i >= 0:
                newcorr = struct.pack('<L', corrle-i)
                hccaps += pack_jtr(hccap, hccapx, essid, newcorr, -i, 'LE')
            #BE+
            if corrbe+i <= 4294967295:
                newcorr = struct.pack('>L', corrbe+i)
                hccaps += pack_jtr(hccap, hccapx, essid, newcorr, i, 'BE')
            #BE-
            if corrbe-i >= 0:
                newcorr = struct.pack('>L', corrbe-i)
                hccaps += pack_jtr(hccap, hccapx, essid, newcorr, -i, 'BE')

        return hccaps

    def prepare_work(self, netdata, etype):
        '''prepare work based on netdata; returns dictname'''
        if netdata is None:
            return False

        try:
            if etype == 'hccapx':
                handshake = base64.b64decode(netdata['hccapx'])
            else:
                handshake = self.hccapx2john(base64.b64decode(netdata['hccapx']))

            #write net
            try:
                try:
                    with open(self.conf['net_file'], 'wb') as fd:
                        fd.write(handshake)
                except TypeError:
                    with open(self.conf['net_file'], 'w') as fd:
                        fd.write(handshake)

            except OSError as e:
                self.pprint('Handshake write failed', 'FAIL')
                self.pprint('Exception: {0}'.format(e), 'FAIL')
                return False

            #check for dict and download it
            if 'dpath' not in netdata:
                return True
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
                                chunk = ftgz.read(self.blocksize)
                                if not chunk:
                                    break
                                fd.write(chunk)
                except (IOError, OSError, EOFError, zlib.error) as e:
                    self.pprint(gzdictname + ' extraction failed', 'FAIL')
                    self.pprint('Exception: {0}'.format(e), 'FAIL')
                    return False

            return dictname

        except TypeError as e:
            self.pprint('Exception: {0}'.format(e), 'FAIL')

        return False

    def prepare_challenge(self, etype):
        '''prepare chalenge files with known PSK'''
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
            #create dict
            try:
                data = netdata['key'] + "\n"
                with open(netdata['dictname'], 'wb') as fd:
                    fd.write(data.encode())
            except OSError as e:
                self.pprint(netdata['dictname'] + ' creation failed', 'FAIL')
                self.pprint('Exception: {0}'.format(e), 'FAIL')
                exit(1)

            return netdata
        except TypeError as e:
            self.pprint('Couldn\'t prepare challenge', 'FAIL')
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            exit(1)

    def put_work(self, handshakehash, pwkey):
        '''return results to server'''
        try:
            data = urlencode({handshakehash: pwkey}).encode()
            response = urlopen(self.conf['put_work_url'], data)
        except IOError as e:
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            return False

        response.close()

        return True

    def create_resume(self, netdata):
        '''create resume file'''
        with open(self.conf['res_file'], 'w') as fd:
            json.dump(netdata, fd)

    def resume_check(self):
        '''check for resume files'''
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

    def run_cracker(self, tool, dictname, performance='', rule='', disablestdout=False):
        '''run externel cracker process'''
        while True:
            try:
                if tool.find('ashcat') != -1:
                    try:
                        if disablestdout:
                            fd = open(os.devnull, 'w')
                        else:
                            fd = None
                        cracker = '{0} -m2500 --nonce-error-corrections=128 --outfile-autohex-disable --potfile-disable --outfile-format=2 {1} -o{2} {3} {4} {5}'.format(tool, performance, self.conf['key_file'], rule, self.conf['net_file'], dictname)
                        subprocess.check_call(shlex.split(cracker), stdout=fd)
                    except subprocess.CalledProcessError as ex:
                        if fd:
                            fd.close()
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
                            self.pprint('hashcat {0} died with code {1}'.format(tool, ex.returncode), 'FAIL')
                            self.pprint('Check you have OpenCL support', 'FAIL')
                            exit(1)

                if tool.find('john') != -1:
                    try:
                        if disablestdout:
                            fd = open(os.devnull, 'w')
                        else:
                            fd = None
                        cracker = '{0} {1} --pot={2} --wordlist={3} {4}'.format(tool, performance, self.conf['key_file'], dictname, self.conf['net_file'])
                        subprocess.check_call(shlex.split(cracker), stdout=fd)
                    except subprocess.CalledProcessError as ex:
                        if fd:
                            fd.close()
                        self.pprint('john {0} died with code {1}'.format(tool, ex.returncode), 'FAIL')
                        exit(1)

                    if not os.path.exists(self.conf['key_file']):
                        return 1
                    if os.path.getsize(self.conf['key_file']) == 0:
                        return 1

            except KeyboardInterrupt as ex:
                self.pprint('\nKeyboard interrupt', 'OKBLUE')
                if os.path.exists(self.conf['key_file']):
                    os.unlink(self.conf['key_file'])
                exit(1)

            return 0

    def get_key(self, tool):
        '''read key from file'''
        try:
            if tool.find('ashcat') != -1:
                if os.path.exists(self.conf['key_file']):
                    with open(self.conf['key_file'], 'r') as fd:
                        key = fd.readline()
                    key = key.rstrip('\n')
                    if len(key) >= 8:
                        os.unlink(self.conf['key_file'])
                        return key

            if tool.find('john') != -1:
                if os.path.exists(self.conf['key_file']):
                    with open(self.conf['key_file'], 'r') as fd:
                        key = fd.readline()
                    key = key.rstrip('\n')[100:]
                    key = key[key.find(':')+1:]
                    if len(key) >= 8:
                        os.unlink(self.conf['key_file'])
                        return key
        except IOError as e:
            self.pprint('Couldn\'t read key', 'FAIL')
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            exit(1)

        return None

    def run(self):
        '''entry point'''
        self.check_version()
        tool = self.check_tools()

        #set format
        if tool.find('ashcat') != -1:
            fformat = 'hccapx'
        else:
            fformat = 'wpapsk'

        #run hashcat in performance tune mode
        performance = ''
        if tool.find('ashcat') != -1:
            performance = '-w 3'

        #challenge the cracker
        self.pprint('Challenge cracker for correct results', 'OKBLUE')
        netdata = self.prepare_challenge(fformat)
        self.prepare_work(netdata, fformat)
        rc = self.run_cracker(tool, netdata['dictname'], performance, disablestdout=True)
        key = self.get_key(tool)

        if rc != 0 or key != netdata['key']:
            self.pprint('Challenge solving failed! Check if your cracker runs correctly.', 'FAIL')
            exit(1)

        netdata = self.resume_check()

        while True:
            if netdata is None:
                netdata = self.get_work_wl(json.JSONEncoder().encode({'format': fformat, 'tool': os.path.basename(tool)}))
                if netdata:
                    self.create_resume(netdata)

            while True:
                dictname = self.prepare_work(netdata, fformat)
                if not dictname:
                    self.pprint('Couldn\'t prepare data', 'WARNING')
                    self.sleepy(10)
                    continue
                break

            #check if we will use rules
            rule = ''
            if 'rule' in netdata and tool.find('ashcat') != -1 and os.path.exists(netdata['rule']):
                rule = '-r' + netdata['rule']

            rc = self.run_cracker(tool, dictname, performance, rule)
            if rc == 0:
                key = self.get_key(tool)
                self.pprint('Key for capture hash {0} is: {1}'.format(netdata['hash'], key.encode(sys.stdout.encoding or 'utf-8', errors='xmlcharrefreplace')), 'OKGREEN')
                while not self.put_work(netdata['hash'], key):
                    self.pprint('Couldn\'t submit key', 'WARNING')
                    self.sleepy()

            #cleanup
            if os.path.exists(self.conf['net_file']):
                os.unlink(self.conf['net_file'])
            if os.path.exists(self.conf['res_file']):
                os.unlink(self.conf['res_file'])
            netdata = None


if __name__ == "__main__":
    print('help_crack, distributed WPA cracker, v{0}\nsite: {1}'.format(conf['hc_ver'], conf['base_url']))

    if len(sys.argv) > 1:
        print('Usage: {0} : download capture and wordlist then start cracking'.format(sys.argv[0]))
        exit(1)

    hc = HelpCrack(conf)
    hc.run()
