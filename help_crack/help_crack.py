#!/usr/bin/env python
'''Clientside part of dwpa distributed cracker
The source code is distributed under GPLv3+ license
author: Alex Stanev, alex at stanev dot org
web: https://wpa-sec.stanev.org'''

from __future__ import print_function
import argparse
import sys
import os
import subprocess
import shlex
import stat
import hashlib
import zlib
import gzip
import re
import time
import json
import binascii
import struct
from distutils.version import StrictVersion
from functools import partial

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
    maketrans = bytearray.maketrans  # pylint: disable=no-member

try:
    userinput = raw_input
except NameError:
    userinput = input

# configuration
conf = {
    'base_url': 'https://wpa-sec.stanev.org/',
    'res_file': 'help_crack.res',
    'hccapx_file': 'help_crack.hccapx',
    'pmkid_file': 'help_crack.pmkid',
    'key_file': 'help_crack.key',
    'additional': None,
    'custom': None,
    'format': None,
    'potfile': None,
    'cracker': '',
    'coptions': '',
    'dictcount': 1,
    'autodictcount': True,
    'hc_ver': '1.1.1'
}
conf['help_crack'] = conf['base_url'] + 'hc/help_crack.py'
conf['help_crack_cl'] = conf['base_url'] + 'hc/CHANGELOG'
conf['get_work_url'] = conf['base_url'] + '?get_work'
conf['put_work_url'] = conf['base_url'] + '?put_work'


class HelpCrack(object):
    '''Main helpcrack class'''
    # decompression block size 64k
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
        try:
            time.sleep(sec)
        except KeyboardInterrupt:
            self.pprint('\nKeyboard interrupt', 'OKBLUE')
            exit(0)

    @staticmethod
    def valid_mac(mac):
        '''validate bssid/mac address'''
        if len(mac) != 17:
            return False
        return bool(re.match(r'^([a-f0-9]{2}\:?){6}$', mac))

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
        while True:
            try:
                urlretrieve(url, filename)
                return True
            except IOError as e:
                self.pprint('Exception: {0}'.format(e), 'FAIL')
                self.sleepy()

    def get_url(self, url, options=None):
        '''get remote content and return it in var'''
        try:
            data = urlencode({'options': options}).encode()
            response = urlopen(url, data)
        except IOError as e:
            self.pprint('Exception: {0}'.format(e), 'WARNING')
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
                self.pprint(f'New version {remoteversion} of help_crack found.')
                user = userinput('Update[y] or Show changelog[c]:')
                if user == 'c':
                    self.pprint(self.get_url(self.conf['help_crack_cl']))
                    continue
                if user in ['y', '']:
                    if self.download(
                        self.conf['help_crack'], f'{sys.argv[0]}.new'
                    ):
                        try:
                            os.rename(f'{sys.argv[0]}.new', sys.argv[0])
                            os.chmod(sys.argv[0], stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
                        except OSError as e:
                            self.pprint('Exception: {0}'.format(e), 'FAIL')
                            # TODO: think of workaround locking on win32
                            if os.name == 'nt':
                                self.pprint('You are running under win32, rename help_crack.py.new over help_crack.py', 'OKBLUE')
                        self.pprint('help_crack updated, run again', 'OKGREEN')
                        exit(0)
                    else:
                        self.pprint('help_crack update failed', 'FAIL')
                        return

                return

    def check_tools(self):
        '''look for cracking tools, check for their capabilities, ask user'''

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
                    return f'./{program}'

            return False

        def run_hashcat(tl):
            '''check hashcat version'''
            def _run_hashcat(tool):
                '''execute and check version'''
                try:
                    acp = subprocess.Popen(
                        shlex.split(f'{tool} -V'),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    output = acp.communicate()[0]
                except OSError:
                    return False

                output = re.sub(r'[^\d\.]', '', output.decode())
                try:
                    if StrictVersion(output) >= StrictVersion('6.0.0'):
                        return True
                except ValueError as e:
                    self.pprint('Unsupported hashcat version', 'FAIL')
                    self.pprint('Exception: {0}'.format(e), 'FAIL')
                    exit(1)

                return False

            tools = []
            for xt in tl:
                t = which(xt)
                if t and _run_hashcat(t):
                    tools.append(t)

            return tools

        def run_jtr():
            '''check JtR capabilities'''
            def _run_jtr(tool):
                '''execute and check'''
                try:
                    acp = subprocess.Popen(shlex.split(tool), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    output = acp.communicate()[0]
                except OSError:
                    return False

                return output.find(b'PASS') != -1 and output.find(b'PMKID') != -1

            tools = []
            t = which('john')
            if t:
                if _run_jtr(f'{t} --format=wpapsk --test=0'):
                    tools.append(f'{t} --format=wpapsk')
                if _run_jtr(f'{t} --format=wpapsk-opencl --test=0'):
                    tools.append(f'{t} --format=wpapsk-opencl')
                if _run_jtr(f'{t} --format=wpapsk-cuda --test=0'):
                    tools.append(f'{t} --format=wpapsk-cuda')

            return tools

        def set_format(tool):
            '''sets format based on selected tool'''
            self.conf['cracker'] = tool
            self.conf['format'] = 'hccapx' if tool.find('hashcat') != -1 else 'wpapsk'
            return

        tools = []

        # hashcat
        tools += run_hashcat(['hashcat', 'hashcat.bin'])

        # John the Ripper
        tools += run_jtr()

        if not tools:
            self.pprint('hashcat or john not found', 'FAIL')
            exit(1)
        if len(tools) == 1:
            set_format(tools[0])
            return tools[0]

        self.pprint('Choose the tool for cracking:')
        for index, ttool in enumerate(tools):
            print('{0}: {1}'.format(index, ttool))
        print('9: Quit')
        while True:
            user = userinput('Index:')
            if user == '9':
                exit(0)
            try:
                set_format(tools[int(user)])
                return tools[int(user)]
            except (ValueError, IndexError):
                self.pprint('Wrong index', 'WARNING')

    @staticmethod
    def hccapx2john(hccapx):
        '''convert hccapx struct to JtR $WPAPSK$ and implement nonce correction
            hccap:  https://hashcat.net/wiki/doku.php?id=hccap
            hccapx: https://hashcat.net/wiki/doku.php?id=hccapx
            JtR:    https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/src/wpapcap2john.c
        '''

        def pack_jtr(hccap, message_pair, ncorr=0):
            '''prepare handshake in JtR format'''
            jtr = b'%s:$WPAPSK$%s#%s:%s:%s:%s::%s:%s:/dev/null\n'
            hccap_fmt = '< 36s 6s 6s 32x 28x 4s 256x 4x I 16x'

            (essid, mac_ap, mac_sta, corr, keyver) = struct.unpack(hccap_fmt, hccap)

            # replay count checked
            ver = b'verified' if message_pair & 0x80 > 1 else b'not verified'
            # detect endian and apply nonce correction
            if ncorr != 0:
                try:
                    if message_pair & 0x40 > 1:
                        ver += b', fuzz ' + str(ncorr).encode() + b' BE'
                        dcorr = struct.unpack('>L', corr)[0]
                        corr = struct.pack('>L', dcorr + ncorr)
                    if message_pair & 0x20 > 1:
                        ver += b', fuzz ' + str(ncorr).encode() + b' LE'
                        dcorr = struct.unpack('<L', corr)[0]
                        corr = struct.pack('<L', dcorr + ncorr)
                except struct.error:
                    pass

            # cut essid part and stuff correction
            newhccap = hccap[36:108] + corr + hccap[112:]

            # prepare values for JtR
            essid = essid.rstrip(b'\0')
            mac_sta = binascii.hexlify(mac_sta)
            mac_ap = binascii.hexlify(mac_ap)

            if keyver == 1:
                keyver = b'WPA'
            elif keyver == 2:
                keyver = b'WPA2'
            elif keyver >= 3:
                keyver = b'WPA CMAC'

            # prepare translation to base64 alphabet used by JtR
            encode_trans = maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
                                     b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')

            return jtr % (essid,
                          essid,
                          binascii.b2a_base64(newhccap).translate(encode_trans).rstrip(b'=\r\n'),
                          mac_sta,
                          mac_ap,
                          mac_ap,
                          keyver,
                          ver)

        def hccapx2hccap(hccapx):
            '''convert hccapx to hccap struct'''
            hccapx_fmt = '< 4x 4x B x 32s B 16s 6s 32s 6s 32s H 256s'
            hccap_fmt = '< 36s 6s 6s 32s 32s 256s I I 16s'

            (message_pair,
             essid,
             keyver, keymic,
             mac_ap, nonce_ap, mac_sta, nonce_sta,
             eapol_len, eapol) = struct.unpack(hccapx_fmt, hccapx)

            hccap = struct.pack(
                hccap_fmt,
                essid,
                mac_ap, mac_sta,
                nonce_sta, nonce_ap,
                eapol, eapol_len,
                keyver, keymic)

            return (hccap, message_pair)

        hccapx = bytearray(hccapx)

        # convert hccapx to hccap and extract message_pair
        (hccap, message_pair) = hccapx2hccap(hccapx)

        # exact handshake
        hccaps = pack_jtr(hccap, message_pair)
        if message_pair & 0x10 > 1:
            return hccaps

        # detect if we have endianness info
        flip = False
        if message_pair & 0x60 == 0:
            flip = True
            # set flag for LE
            message_pair |= 0x20

        # prepare nonce correction
        for i in range(1, 8):
            if flip:
                # this comes with LE set first time if we don't have endianness info
                hccaps += pack_jtr(hccap, message_pair, i)
                hccaps += pack_jtr(hccap, message_pair, -i)
                # toggle BE/LE bits
                message_pair ^= 0x60

            hccaps += pack_jtr(hccap, message_pair, i)
            hccaps += pack_jtr(hccap, message_pair, -i)

        return hccaps

    def get_work(self, options):
        '''pull handshakes and optionally dictionary location/ssid'''
        while True:
            work = self.get_url(self.conf['get_work_url']+'='+self.conf['hc_ver'], options)
            try:
                netdata = json.loads(work)
                if all('ssid' not in d for d in netdata) and all(
                    'hkey' not in d for d in netdata
                ):
                    raise ValueError

                return netdata
            except (TypeError, ValueError, KeyError):
                if work == 'Version':
                    self.pprint('Please update help_crack, the API has changed', 'FAIL')
                    exit(1)
                if 'ssid' in options and work == 'No nets':
                    self.pprint('User dictionary check finished', 'OKGREEN')
                    exit(0)
                if work == 'No nets':
                    self.pprint('No suitable nets found', 'WARNING')
                    self.sleepy()
                    continue

            self.pprint('Server response error', 'WARNING')
            self.sleepy()

    def prepare_work(self, netdata):
        '''prepare work based on netdata; returns ssid/hkey'''
        if netdata is None:
            return False

        # cleanup
        if os.path.exists(self.conf['hccapx_file']):
            os.unlink(self.conf['hccapx_file'])
        if os.path.exists(self.conf['pmkid_file']):
            os.unlink(self.conf['pmkid_file'])

        # extract ssid/hkey and handshakes
        metadata = {}
        try:
            for part in netdata:
                if 'hkey' in part:
                    metadata['hkey'] = part['hkey']
                if 'ssid' in part:
                    metadata['ssid'] = part['ssid']
                if 'hccapx' in part:
                    with open(self.conf['hccapx_file'], 'ab') as fd:
                        if self.conf['format'] == 'hccapx':
                            fd.write(binascii.a2b_base64(part['hccapx']))
                        else:
                            fd.write(self.hccapx2john(binascii.a2b_base64(part['hccapx'])))
                if 'pmkid' in part:
                    if self.conf['format'] == 'hccapx':
                        with open(self.conf['pmkid_file'], 'ab') as fd:
                            fd.write(str(part['pmkid']).encode() + b'\n')
                    else:
                        with open(self.conf['hccapx_file'], 'ab') as fd:
                            fd.write(str(part['pmkid']).encode() + b'\n')

            if all('ssid' not in d for d in netdata) and all(
                'hkey' not in d for d in netdata
            ):
                self.pprint('hkey or ssid not found in work package!', 'FAIL')
                exit(1)
        except OSError as e:
            self.pprint('Handshake write failed', 'FAIL')
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            exit(1)

        return metadata

    def prepare_dicts(self, netdata):
        '''download and check dictionaries'''
        # pull dicts info from netdata
        dicts = []
        dlist = []
        dhash = ''
        dpath = ''
        for part in netdata:
            if 'dhash' in part:
                dhash = part['dhash']
            if 'dpath' in part:
                dpath = part['dpath']
            if 'dicts' in part:
                dicts.extend(
                    {'dhash': dpart['dhash'], 'dpath': dpart['dpath']}
                    for dpart in part['dicts']
                )
        if dhash != '' and dpath != '':
            dicts.append({'dhash': dhash, 'dpath': dpath})

        # download and check
        for d in dicts:
            dictmd5 = ''
            extract = False
            gzdictname = d['dpath'].split('/')[-1]
            dictname = gzdictname.rsplit('.', 1)[0]
            dlist.append(dictname)

            while True:
                if os.path.exists(gzdictname):
                    dictmd5 = self.md5file(gzdictname)
                if d['dhash'] != dictmd5:
                    self.pprint('Downloading {0}'.format(gzdictname), 'OKBLUE')
                    self.download(d['dpath'], gzdictname)
                    if self.md5file(gzdictname) != d['dhash']:
                        self.pprint('{0} downloaded but hash mismatch'.format(gzdictname), 'WARNING')

                    extract = True

                if not os.path.exists(dictname):
                    extract = True

                if extract:
                    self.pprint('Extracting {0}'.format(gzdictname), 'OKBLUE')
                    try:
                        with gzip.open(gzdictname, 'rb') as ftgz:
                            with open(dictname, 'wb') as fd:
                                while True:
                                    if chunk := ftgz.read(self.blocksize):
                                        fd.write(chunk)
                                    else:
                                        break
                    except (IOError, OSError, EOFError, zlib.error) as e:
                        self.pprint('{0} extraction failed'.format(gzdictname), 'FAIL')
                        self.pprint('Exception: {0}'.format(e), 'FAIL')
                        self.sleepy()
                        continue
                break

        return dlist

    def prepare_challenge(self):
        '''prepare challenge with known PSK'''
        netdata = [{'hccapx': """SENQWAQAAAAABWRsaW5rAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiaaYe8l4TWktCODLsTs\
                                x/QcfuXi8tDb0kmj6c7GztM2D7o/rpukqm7Gx2EFeW/2taIJ0YeCygAmxy5JAGRbH2hKJWbiEmbx\
                                I6vDhsxXb1k+bcXjgjoy+9Svkp9RewABAwB3AgEKAAAAAAAAAAAAAGRbH2hKJWbiEmbxI6vDhsxX\
                                b1k+bcXjgjoy+9Svkp9RAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                                AAAAAAAAABgwFgEAAA+sAgEAAA+sBAEAAA+sAjwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""",
                    'pmkid': '8ac36b891edca8eef49094b1afe061ac*1c7ee5e2f2d0*0026c72e4900*646c696e6b',
                    'key': 'aaaa1234',
                    'dictname': 'challenge.txt'},
                   {'ssid': ''}]
        try:
            # create dict
            try:
                data = netdata[0]['key'] + "\n"
                with open(netdata[0]['dictname'], 'wb') as fd:
                    fd.write(data.encode())
            except OSError as e:
                self.pprint(netdata[0]['dictname'] + ' creation failed', 'FAIL')
                self.pprint('Exception: {0}'.format(e), 'FAIL')
                exit(1)

            # clean old keyfile
            if os.path.exists(self.conf['key_file']):
                os.unlink(self.conf['key_file'])

            return netdata
        except TypeError as e:
            self.pprint('Couldn\'t prepare challenge', 'FAIL')
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            exit(1)

    def put_work(self, metadata, keypair):
        '''return results to server'''
        keys = {}
        if 'hkey' in metadata:
            keys['hkey'] = metadata['hkey']
        if keypair is not None:
            for pad, k in enumerate(keypair):
                keys[(b'z%03d' % pad) + k['bssid']] = k['key']
        data = urlencode(keys).encode()
        while True:
            try:
                response = urlopen(self.conf['put_work_url'], data)
                response.close()
                return True
            except IOError as e:
                self.pprint('Couldn\'t submit key', 'WARNING')
                self.pprint('Exception: {0}'.format(e), 'WARNING')
                self.sleepy(10)

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
                    if all('ssid' not in d for d in netdata) and all(
                        'hkey' not in d for d in netdata
                    ):
                        raise ValueError
                    if (
                        all('hkey' not in d for d in netdata)
                        and self.conf['custom'] is None
                    ):
                        self.pprint('Can\'t resume from custom dictionary attack', 'WARNING')
                        return None
                    if any('hkey' in d for d in netdata) and self.conf['custom'] is not None:
                        self.pprint('Can\'t resume from classic aatack to custom dictionary', 'WARNING')
                        return None
                    self.pprint('Session resume', 'OKBLUE')
                    return netdata
                except (TypeError, ValueError, KeyError):
                    self.pprint('Bad resume file contents', 'WARNING')
                    os.unlink(self.conf['res_file'])

        return None

    def run_cracker(self, dictlist, disablestdout=False):
        '''run external cracker process'''
        fd = open(os.devnull, 'w') if disablestdout else None
        while True:
            try:
                # TODO: fix this code duplication
                if self.conf['format'] == 'hccapx':
                    if os.path.exists(self.conf['pmkid_file']):
                        cracker = '{0} -m16800 --advice-disable --logfile-disable --potfile-disable {1} -o{2} {3}'.format(self.conf['cracker'], self.conf['coptions'], self.conf['key_file'], self.conf['pmkid_file'])
                        for dn in dictlist:
                            cracker = ''.join([cracker, ' ', dn])
                        rc = subprocess.call(shlex.split(cracker), stdout=fd)
                        if rc == -2:
                            self.pprint('Thermal watchdog barked', 'WARNING')
                            self.sleepy()
                            continue
                        if rc >= 2 or rc == -1:
                            self.pprint('hashcat {0} died with code {1}'.format(self.conf['cracker'], rc), 'FAIL')
                            self.pprint('Check you have OpenCL support', 'FAIL')
                            exit(1)

                    if os.path.exists(self.conf['hccapx_file']):
                        cracker = '{0} -m2500 --nonce-error-corrections=8 --advice-disable --logfile-disable --potfile-disable {1} -o{2} {3}'.format(self.conf['cracker'], self.conf['coptions'], self.conf['key_file'], self.conf['hccapx_file'])
                        for dn in dictlist:
                            cracker = ''.join([cracker, ' ', dn])
                        rc = subprocess.call(shlex.split(cracker), stdout=fd)
                        if rc == -2:
                            self.pprint('Thermal watchdog barked', 'WARNING')
                            self.sleepy()
                            continue
                        if rc >= 2 or rc == -1:
                            self.pprint('hashcat {0} died with code {1}'.format(self.conf['cracker'], rc), 'FAIL')
                            self.pprint('Check you have OpenCL support', 'FAIL')
                            exit(1)

                # TODO: use multiple -w:, when/if availible, see https://github.com/magnumripper/JohnTheRipper/issues/3262
                if self.conf['format'] == 'wpapsk':
                    dp = 'type ' if os.name == 'nt' else 'cat '
                    for dn in dictlist:
                        dp = ''.join([dp, ' ', dn])
                    cracker = '{0} {1} --stdin --pot={2} {3}'.format(self.conf['cracker'], self.conf['coptions'], self.conf['key_file'], self.conf['hccapx_file'])
                    p1 = subprocess.Popen(shlex.split(dp), stdout=subprocess.PIPE)
                    p2 = subprocess.Popen(shlex.split(cracker), stdin=p1.stdout, stdout=subprocess.PIPE)
                    p1.stdout.close()
                    p2.communicate()

            except KeyboardInterrupt:
                self.pprint('\nKeyboard interrupt', 'OKBLUE')
                exit(0)

            if fd:
                fd.close()

            return

    def get_key(self):
        '''read bssid and key pairs from file'''

        def parse_hashcat(pot):
            '''parse hashcat potfile line'''
            try:
                arr = pot.split(b':', 4)
                bssid = arr[1][:12]
                bssid = (
                    (
                        (
                            (
                                (
                                    (
                                        (((bssid[:2] + b':') + bssid[2:4]) + b':')
                                        + bssid[4:6]
                                    )
                                    + b':'
                                )
                                + bssid[6:8]
                            )
                            + b':'
                        )
                        + bssid[8:10]
                    )
                    + b':'
                ) + bssid[10:12]
                return {'bssid': bssid, 'key': arr[4].rstrip(b'\r\n')}
            except (TypeError, ValueError, KeyError, IndexError):
                pass

            return False

        def parse_jtr(pot):
            '''parse JtR potfile line'''
            def jb64decode(jb64):
                '''JtR b64 decode'''
                encode_trans = maketrans(b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                                         b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
                b64 = jb64.translate(encode_trans) + b'='

                return binascii.a2b_base64(b64)

            arr = pot.split(b':', 1)
            if len(arr) != 2:
                return False
            key = arr[1].rstrip(b'\r\n')

            arr = arr[0].split(b'#', 1)
            if len(arr) != 2:
                return False

            try:
                phccap = jb64decode(arr[1])
                bssid = binascii.hexlify(phccap[:6])
                bssid = (
                    (
                        (
                            (
                                (
                                    (
                                        (((bssid[:2] + b':') + bssid[2:4]) + b':')
                                        + bssid[4:6]
                                    )
                                    + b':'
                                )
                                + bssid[6:8]
                            )
                            + b':'
                        )
                        + bssid[8:10]
                    )
                    + b':'
                ) + bssid[10:12]
            except (binascii.Error, binascii.Incomplete):
                return False

            return {'bssid': bssid, 'key': key}

        def parse_pmkid(pot):
            '''parse PMKID potfile line'''
            try:
                arr = pot.split(b':', 1)
                arr1 = arr[0].split(b'*', 3)
                bssid = arr1[1]
                bssid = (
                    (
                        (
                            (
                                (
                                    (
                                        (((bssid[:2] + b':') + bssid[2:4]) + b':')
                                        + bssid[4:6]
                                    )
                                    + b':'
                                )
                                + bssid[6:8]
                            )
                            + b':'
                        )
                        + bssid[8:10]
                    )
                    + b':'
                ) + bssid[10:12]
                return {'bssid': bssid, 'key': arr[1].rstrip(b'\r\n')}
            except (TypeError, ValueError, KeyError, IndexError):
                pass

            return False

        def parse_hashcat_combined(pot):
            '''parse hashcat combined potfile line'''
            try:
                arr = pot.split(b':', 3)
                if len(arr[0]) != 12:
                    raise ValueError
                bssid = arr[0]
                bssid = (
                    (
                        (
                            (
                                (
                                    (
                                        (((bssid[:2] + b':') + bssid[2:4]) + b':')
                                        + bssid[4:6]
                                    )
                                    + b':'
                                )
                                + bssid[6:8]
                            )
                            + b':'
                        )
                        + bssid[8:10]
                    )
                    + b':'
                ) + bssid[10:12]
                return {'bssid': bssid, 'key': arr[3].rstrip(b'\r\n')}
            except (TypeError, ValueError, KeyError, IndexError):
                pass

            return False

        res = []
        try:
            if os.path.exists(self.conf['key_file']):
                with open(self.conf['key_file'], 'rb') as fd:
                    while True:
                        line = fd.readline()
                        if not line:
                            break

                        # check if we have user potfile. Don't write if it's the challenge
                        if self.conf['potfile'] and not \
                                (b'76c6eaf116d91cc1450561b00c98ea19' in line
                             or b'55vZsj9E.0P59YY.N3gTO2cZNi6GNj2XewC4n3RjKH' in line
                             or b'8ac36b891edca8eef49094b1afe061acd0*1c7ee5e2f2d0' in line
                             or b'1c7ee5e2f2d0:0026c72e4900:dlink:aaaa1234' in line):
                            with open(self.conf['potfile'], 'ab') as fdpot:
                                fdpot.write(line)

                        keypair = parse_hashcat_combined(line)
                        if keypair:
                            res.append(keypair)
                            continue
                        keypair = parse_hashcat(line)
                        if keypair:
                            res.append(keypair)
                            continue
                        keypair = parse_jtr(line)
                        if keypair:
                            res.append(keypair)
                            continue
                        keypair = parse_pmkid(line)
                        if keypair:
                            res.append(keypair)
                            continue

            if res:
                os.unlink(self.conf['key_file'])
                return res
        except IOError as e:
            self.pprint('Couldn\'t read pot file', 'FAIL')
            self.pprint('Exception: {0}'.format(e), 'FAIL')
            exit(1)

        return None

    def run(self):
        '''entry point'''
        self.check_version()
        self.check_tools()

        # challenge the cracker
        self.pprint('Challenge cracker for correct results', 'OKBLUE')
        netdata = self.prepare_challenge()
        self.prepare_work(netdata)
        self.run_cracker([netdata[0]['dictname']], disablestdout=True)
        keypair = self.get_key()

        if not keypair \
                    or len(keypair) != 2 \
                    or keypair[0]['key'] != bytearray(netdata[0]['key'], 'utf-8', errors='ignore') \
                    or keypair[1]['key'] != bytearray(netdata[0]['key'], 'utf-8', errors='ignore'):
            self.pprint('Challenge solving failed! Check if your cracker runs correctly.', 'FAIL')
            exit(1)

        hashcache = set()
        netdata = self.resume_check()
        metadata = {'ssid': '00'}
        options = {'format': self.conf['format'], 'cracker': self.conf['cracker'], 'dictcount': self.conf['dictcount']}
        while True:
            if netdata is None:
                if self.conf['custom']:
                    options['ssid'] = metadata['ssid']
                netdata = self.get_work(json.JSONEncoder().encode(options))

            self.create_resume(netdata)
            metadata = self.prepare_work(netdata)

            # add custom dict or prepare remote ones
            if self.conf['custom']:
                dictlist = [self.conf['custom']]
            else:
                dictlist = self.prepare_dicts(netdata)

            # do we have additional user dictionary supplied?
            if conf['additional'] is not None:
                # compute handshakes simple hash
                ndhash = 0
                for part in netdata:
                    if 'hccapx' in part:
                        ndhash ^= hash(part['hccapx'])
                if ndhash not in hashcache:
                    hashcache.add(ndhash)
                    dictlist.append(conf['additional'])

            # run cracker and collect results
            cstart = time.time()
            self.run_cracker(dictlist)
            cdiff = int(time.time() - cstart)
            if self.conf['autodictcount'] and not self.conf['custom']:
                if options['dictcount'] < 15 and cdiff < 300:  # 5 min
                    options['dictcount'] += 1
                    self.pprint('Incrementing dictcount to {0}, last duration {1}s'.format(options['dictcount'], cdiff), 'OKBLUE')
                if options['dictcount'] > 1 and cdiff > 300:
                    options['dictcount'] -= 1
                    self.pprint('Decrementing dictcount to {0}, last duration {1}s'.format(options['dictcount'], cdiff), 'OKBLUE')

            keypair = self.get_key()
            if keypair:
                for k in keypair:
                    try:
                        self.pprint('Key for bssid {0} is: {1}'.format(k['bssid'].decode(sys.stdout.encoding or 'utf-8', errors='ignore'),
                                                                       k['key'].decode(sys.stdout.encoding or 'utf-8', errors='ignore')), 'OKGREEN')
                    except UnicodeEncodeError:
                        pass
            self.put_work(metadata, keypair)

            # cleanup
            if os.path.exists(self.conf['res_file']):
                os.unlink(self.conf['res_file'])
            netdata = None


if __name__ == "__main__":
    def is_valid_file(aparser, arg):
        '''check if it's a valid file'''
        if not os.path.isfile(arg):
            aparser.error(f'The file {arg} does not exist!')
        return arg

    def is_valid_dc(aparser, arg):
        '''check if it's a valid dict count'''
        iarg = int(arg)
        if iarg <= 0 or iarg > 15:
            aparser.error('dictionaries count must be between 1 and 15')
        return arg

    parser = argparse.ArgumentParser(description='help_crack, distributed WPA cracker site: {0}'.format(conf['base_url']))
    parser.add_argument('-v', '--version', action='version', version=conf['hc_ver'])
    parser.add_argument('-co', '--coptions', type=str, help='custom options, that will be supplied to cracker. Those must be passed as -co="--your_option"')
    parser.add_argument('-pot', '--potfile', type=str, help='preserve cracked results in user supplied pot file')
    parser.add_argument('-dc', '--dictcount', type=lambda x: is_valid_dc(parser, x), help='count of dictionaries to be downloaded and checked against')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-ad', '--additional', type=lambda x: is_valid_file(parser, x), help='additional user dictionary to be checked after downloaded one')
    group.add_argument('-cd', '--custom', type=lambda x: is_valid_file(parser, x), help='custom user dictionary to be checked against all uncracked handshakes')

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(str(e))

    conf['additional'] = args.additional
    conf['custom'] = args.custom
    if args.coptions:
        conf['coptions'] = args.coptions
    if args.potfile:
        conf['potfile'] = args.potfile
    if args.dictcount:
        conf['dictcount'] = args.dictcount
        conf['autodictcount'] = False

    hc = HelpCrack(conf)
    hc.run()
