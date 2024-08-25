#!/usr/bin/env python3
"""
Clientside part of dwpa distributed cracker
The source code is distributed under GPLv3+ license
author: Alex Stanev, alex at stanev dot org
web: https://wpa-sec.stanev.org
"""

import argparse
import sys
import os
import subprocess
import shlex
import stat
import gzip
import re
import time
import json
import binascii
import struct
import socket
import signal
from hashlib import md5
from urllib.request import Request, urlopen, urlretrieve


# configuration
conf = {
    "base_url"      : "https://wpa-sec.stanev.org/",
    "res_file"      : "help_crack.res",
    "hash_file"     : "help_crack.hash",
    "key_file"      : "help_crack.key",
    "rules_file"    : "help_crack.rules",
    "additional"    : None,
    "format"        : None,
    "potfile"       : None,
    "cracker"       : "",
    "coptions"      : "",
    "rules"         : "",
    "hc_ver"        : "2.1.1",
    "hashcat_ver"   : "6.2.6"
}
conf["help_crack"]    = f"{conf['base_url']}hc/help_crack.py"
conf["help_crack_cl"] = f"{conf['base_url']}hc/CHANGELOG"
conf["get_work_url"]  = f"{conf['base_url']}?get_work"
conf["put_work_url"]  = f"{conf['base_url']}?put_work"


class HelpCrack():
    """Main helpcrack class"""
    # decompression block size 64k
    blocksize = 1 << 16
    conf = None

    def __init__(self, c=None):
        self.conf = c

    @staticmethod
    def pprint(mess, code="HEADER"):
        """pretty print"""
        if os.name == "nt":
            print(mess)
        else:
            cc = {"HEADER"  : "\033[95m",
                  "OKBLUE"  : "\033[94m",
                  "OKGREEN" : "\033[92m",
                  "WARNING" : "\033[93m",
                  "FAIL"    : "\033[91m",
                  "ENDC"    : "\033[0m"
                 }
            print(f"{cc[code]}{mess}{cc['ENDC']}")

    def sleepy(self, sec=222):
        """wait for calm down"""
        self.pprint("Sleeping...", "WARNING")
        try:
            time.sleep(sec)
        except KeyboardInterrupt:
            self.pprint("\nKeyboard interrupt", "OKBLUE")
            sys.exit(0)

    def md5file(self, filename):
        """compute md5 over local file"""
        md5sum = md5()
        try:
            with open(filename, "rb") as fd:
                for chunk in iter(lambda: fd.read(self.blocksize), b""):
                    md5sum.update(chunk)
        except OSError as e:
            self.pprint(f"Exception: {e}", "FAIL")
            return None

        return md5sum.hexdigest()

    def download(self, url, filename):
        """download remote file"""
        while True:
            try:
                urlretrieve(url, filename)
                return True
            except IOError as e:
                self.pprint(f"Download exception: {e}", "FAIL")
                self.sleepy()

    def get_url(self, url, payload=None):
        """get remote content and return it in var"""
        if payload is None:
            req = url
        else:
            req = Request(url, data=payload, headers={"Content-Type": "application/json"})

        while True:
            try:
                with urlopen(req) as resp:
                    return resp.read().decode()
            except IOError as e:
                self.pprint(f"Remote request exception: {e}", "WARNING")
                self.sleepy(60)
                continue

    @staticmethod
    def compare_versions(version1, version2):
        """ custom version compare """
        def split_version(version):
            parts = re.split(r"(\d+|\D+)", version)
            return [int(part) if part.isdigit() else part for part in parts if part]

        v1_components = split_version(version1)
        v2_components = split_version(version2)

        # pad the shorter list with zeros or empty strings (if necessary)
        max_length = max(len(v1_components), len(v2_components))
        v1_components.extend([0] * (max_length - len(v1_components)))
        v2_components.extend([0] * (max_length - len(v2_components)))

        # compare component by component
        for v1, v2 in zip(v1_components, v2_components):
            if isinstance(v1, int) and isinstance(v2, int):
                if v1 > v2:
                    return 1
                if v1 < v2:
                    return -1
                # handle alphabetical parts comparison
                if str(v1) > str(v2):
                    return 1
                if str(v1) < str(v2):
                    return -1

        return 0

    def check_version(self):
        """compare version and initiate update"""
        remoteversion = self.get_url(f"{self.conf['help_crack']}.version")
        if not remoteversion:
            self.pprint("Can't check for new version, continue...", "WARNING")
            return
        remoteversion = remoteversion.strip()

        if self.compare_versions(self.conf["hc_ver"], remoteversion) < 0:
            while True:
                self.pprint(f"New version {remoteversion} of help_crack found.")
                user = input("Update[y] or Show changelog[c]:")
                if user == "c":
                    self.pprint(self.get_url(self.conf["help_crack_cl"]))
                    continue
                if user in ("y", ""):
                    if self.download(self.conf["help_crack"], f"{sys.argv[0]}.new"):
                        try:
                            os.rename(sys.argv[0]+".new", sys.argv[0])
                            os.chmod(sys.argv[0], stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
                        except OSError as e:
                            self.pprint(f"Exception: {e}", "FAIL")
                            # TODO: think of workaround locking on win32
                            if os.name == "nt":
                                self.pprint("You are running under Windows. Please rename help_crack.py.new over help_crack.py", "OKBLUE")
                        self.pprint("help_crack updated, run again", "OKGREEN")
                        sys.exit(0)
                    else:
                        self.pprint("help_crack update failed", "FAIL")
                        return

                return

    def check_tools(self):
        """look for cracking tools, check for their capabilities, ask user"""

        def which(program):
            """find executable in current dir or in PATH env var"""
            def is_exe(fpath):
                """check if file exists and is executable"""
                return os.path.exists(fpath) and os.access(fpath, os.X_OK)

            if os.name == "nt":
                program += ".exe"
                if os.path.exists(program):
                    return program

            fpath = os.path.split(program)[0]
            if fpath:
                if is_exe(program):
                    return program
            else:
                for path in os.environ["PATH"].split(os.pathsep):
                    exe_file = os.path.join(path, program)
                    if is_exe(exe_file):
                        return exe_file
                if os.name == "posix" and is_exe(program):
                    return f"./{program}"

            return False

        def run_hashcat():
            """check hashcat version"""
            def _run_hashcat(tool):
                """execute and check version"""
                try:
                    with subprocess.Popen(shlex.split(f"{tool} -V"), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as acp:
                        output = acp.communicate()[0]
                except OSError:
                    return False

                output = output.strip()
                res = re.search(r"(\d+\.\d+\.\d+)", output.decode())
                if res:
                    ver=res.group(1)
                else:
                    self.pprint(f"Can't parse hashcat version: {output.decode()}", "FAIL")
                    sys.exit(1)

                if self.compare_versions(self.conf["hashcat_ver"], ver) <= 0:
                    return True

                self.pprint(f"Unsupported hashcat version {ver}, need minimum {self.conf['hashcat_ver']}", "FAIL")
                sys.exit(1)

            tools = []
            for xt in ["hashcat", "hashcat.bin"]:
                t = which(xt)
                if t and _run_hashcat(t):
                    tools.append(t)

            return tools

        def run_jtr():
            """check JtR capabilities"""
            def _run_jtr(tool):
                """execute and check"""
                try:
                    with subprocess.Popen(shlex.split(tool), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as acp:
                        output = acp.communicate()[0]
                except OSError:
                    return False

                if b"PASS" in output and b"PMKID" in output:
                    return True

                return False

            tools = []
            t = which("john")
            if t:
                if _run_jtr(f"{t} --format=wpapsk --test=0"):
                    tools.append(f"{t} --format=wpapsk")
                if _run_jtr(f"{t} --format=wpapsk-opencl --test=0"):
                    tools.append(f"{t} --format=wpapsk-opencl")
                if _run_jtr(f"{t} --format=wpapsk-cuda --test=0"):
                    tools.append(f"{t} --format=wpapsk-cuda")

            return tools

        def set_format(tool):
            """sets format based on selected tool"""
            self.conf["cracker"] = tool
            if "hashcat" in tool:
                self.conf["format"] = "22000"
            else:
                self.conf["format"] = "wpapsk"

        tools = run_hashcat() + run_jtr()

        if not tools:
            self.pprint("hashcat or john not found", "FAIL")
            sys.exit(1)
        if len(tools) == 1:
            set_format(tools[0])
            return tools[0]

        self.pprint("Choose the tool for cracking:")
        for index, ttool in enumerate(tools):
            print(f"{index}: {ttool}")
        print("9: Quit")
        while True:
            user = input("Index:")
            if user == "9":
                sys.exit(0)
            try:
                set_format(tools[int(user)])
                return tools[int(user)]
            except (ValueError, IndexError):
                self.pprint("Wrong index", "WARNING")

    @staticmethod
    def m22000john(hashline):
        """convert m22000 hashcat hashline to JtR wpapsk"""

        def pack_jtr(hash_arr, message_pair, ncorr=0):
            """ build JtR hashline with given nonce error correction """
            ssid          = bytes.fromhex(hash_arr[5])
            mac_ap        = bytes.fromhex(hash_arr[3])
            mac_sta       = bytes.fromhex(hash_arr[4])
            nonce_sta     = bytes.fromhex(hash_arr[7][34:98])
            nonce_ap_part = bytes.fromhex(hash_arr[6][:56])
            eapol         = bytes.fromhex(hash_arr[7])
            eapol_len     = len(hash_arr[7]) >> 1
            keymic        = bytes.fromhex(hash_arr[2])
            corr          = bytes.fromhex(hash_arr[6][-8:])
            keyver        = struct.unpack("> H", bytes.fromhex(hash_arr[7][10:14]))[0] % 3

            if message_pair & 0x80 > 1:
                ver = "verified"
            else:
                ver = "not verified"

            if ncorr != 0:
                if message_pair & 0x40 > 1:
                    ver = f"{ver}, fuzz {ncorr} BE"
                    dcorr = struct.unpack(">L", corr)[0]
                    corr = struct.pack(">L", dcorr + ncorr)
                if message_pair & 0x20 > 1:
                    ver = f"{ver}, fuzz {ncorr} LE"
                    dcorr = struct.unpack("<L", corr)[0]
                    corr = struct.pack("<L", dcorr + ncorr)

            # JtR struct is missing the ssid field in the beginning
            hccap_john = struct.pack(
                "< 6s 6s 32s 32s 256s I I 16s",
                mac_ap, mac_sta,
                nonce_sta, nonce_ap_part + corr,
                eapol, eapol_len,
                keyver, keymic)

            if keyver == 1:
                keyver = "WPA"
            elif keyver == 2:
                keyver = "WPA2"
            elif keyver == 3:
                keyver = "WPA CMAC"

            # prepare translation to base64 alphabet used by JtR
            encode_trans = bytearray.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                                               b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
            enc_hccap = binascii.b2a_base64(hccap_john).translate(encode_trans).rstrip(b"=\r\n")

            return f"{ssid.decode('utf-8', errors='ignore')}:$WPAPSK${ssid.decode('utf-8', errors='ignore')}#{enc_hccap.decode('utf-8', errors='ignore')}:{hash_arr[4]}:{hash_arr[3]}:{hash_arr[3]}::{keyver}:{ver}:/dev/null\n"

        hash_arr = hashline.split("*", 8)
        if len(hash_arr) != 9 or hash_arr[0] != "WPA":
            return ""

        # PMKID hashline
        if hash_arr[1] == "01":
            return f"{hash_arr[2]}*{hash_arr[3]}*{hash_arr[4]}*{hash_arr[5]}\n"

        # Handshake hashline
        if hash_arr[1] == "02":
            message_pair = int(hash_arr[8], 16)

            # exact the first handshake without nonce error correction
            jtrhashes = pack_jtr(hash_arr, message_pair)

            if message_pair & 0x10 > 1:
                return jtrhashes

            # detect if we have endianness info
            flip = False
            if message_pair & 0x60 == 0:
                flip = True
                # set flag for LE
                message_pair |= 0x20

            # prepare nonce correction
            for i in range(1, 9):
                if flip:
                    # this comes with LE set first time if we don't have endianness info
                    jtrhashes += pack_jtr(hash_arr, message_pair,  i)
                    jtrhashes += pack_jtr(hash_arr, message_pair, -i)
                    # toggle BE/LE bits
                    message_pair ^= 0x60

                jtrhashes += pack_jtr(hash_arr, message_pair,  i)
                jtrhashes += pack_jtr(hash_arr, message_pair, -i)

            return jtrhashes

        return ""

    def get_work(self, dictcount):
        """get new work package"""
        dc = {"dictcount": dictcount}
        dcjson = json.dumps(dc).encode("utf-8")
        while True:
            try:
                response_data = self.get_url(f"{self.conf['get_work_url']}={self.conf['hc_ver']}", dcjson)
                if response_data == "Version":
                    self.pprint("Please update help_crack, the API has changed", "FAIL")
                    sys.exit(1)
                if response_data == "No nets":
                    self.pprint("No suitable nets found", "WARNING")
                    self.sleepy()
                    continue
                netdata = json.loads(response_data)
                if "hkey" not in netdata or "hashes" not in netdata:
                    raise ValueError
                return netdata
            except (TypeError, ValueError) as e:
                self.pprint("Server response error", "WARNING")
                self.pprint(f"Exception: {e}", "WARNING")
                self.sleepy()
                continue

    def prepare_work(self, netdata):
        """prepare work based on netdata; returns ssid/hkey"""
        if netdata is None:
            return False

        # extract hkey, hashes and rules
        metadata = {}
        try:
            if "hkey" in netdata:
                metadata["hkey"] = netdata["hkey"]

            with open(self.conf["hash_file"], "w", encoding="utf-8") as fd:
                for h in netdata["hashes"]:
                    if self.conf["format"] == "22000":
                        fd.write(f"{h}\n")
                        # write rules, just for hashcat for now
                        if "rules" in netdata:
                            with open(self.conf["rules_file"], "wb") as fdr:
                                fdr.write(binascii.a2b_base64(netdata["rules"]))
                                self.conf["rules"] = f"-S -r {self.conf['rules_file']}"
                        else:
                            self.conf["rules"] = ""
                    else:
                        fd.write(self.m22000john(h))
        except OSError as e:
            self.pprint("Hash file write failed", "FAIL")
            self.pprint(f"Exception: {e}", "FAIL")
            sys.exit(1)
        except KeyError as e:
            self.pprint("No hashes found in work package", "FAIL")
            self.pprint(f"Exception: {e}", "FAIL")
            sys.exit(1)

        return metadata

    def prepare_dicts(self, netdata):
        """download and check dictionaries"""

        def read_chunk(gz_file, blocksize):
            return gz_file.read(blocksize)

        dlist = []
        try:
            while True:
                for d in netdata["dicts"]:
                    gzdictname = d["dpath"].split("/")[-1]
                    if not os.path.exists(gzdictname) or d["dhash"] != self.md5file(gzdictname):
                        self.pprint(f"Downloading {gzdictname}", "OKBLUE")
                        self.download(d["dpath"], gzdictname)
                    if self.conf["format"] == "22000":
                        dlist.append(gzdictname)
                    else:
                        dictname = gzdictname.rsplit(".", 1)[0]
                        if not os.path.exists(dictname):
                            self.pprint(f"Extracting {gzdictname}", "OKBLUE")
                            try:
                                with gzip.open(gzdictname, "rb") as gz_file:
                                    with open(dictname, "wb") as fd:
                                        for chunk in iter(lambda: read_chunk(gz_file, self.blocksize), b""):
                                            fd.write(chunk)
                            except (IOError, OSError, EOFError) as e:
                                self.pprint(f"{gzdictname} extraction failed", "FAIL")
                                self.pprint(f"Exception: {e}", "FAIL")
                                self.sleepy()
                                continue
                        dlist.append(dictname)
                break
        except (TypeError, IndexError):
            return None

        return dlist

    def prepare_challenge(self):
        """prepare challenge with known PSK"""
        netdata = {"hashes": ["WPA*01*8ac36b891edca8eef49094b1afe061ac*1c7ee5e2f2d0*0026c72e4900*646c696e6b***",
"""WPA*02*269a61ef25e135a4b423832ec4ecc7f4*1c7ee5e2f2d0*0026c72e4900*646c696e6b*\
dbd249a3e9cec6ced3360fba3fae9ba4aa6ec6c76105796ff6b5a209d18782ca*\
0103007702010a00000000000000000000645b1f684a2566e21266f123abc386\
cc576f593e6dc5e3823a32fbd4af929f51000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000000\
00001830160100000fac020100000fac040100000fac023c000000*00"""],
                    "key": "aaaa1234",
                    "dictname": "help_crack.challenge.dict"
                  }

        try:
            # create dict
            try:
                if self.conf["format"] == "22000":
                    netdata["dictname"] += ".gz"
                    with gzip.open(netdata["dictname"], "w") as fd:
                        fd.write(netdata["key"].encode())
                else:
                    with open(netdata["dictname"], "w", encoding="utf-8") as fd:
                        fd.write(netdata["key"])
            except OSError as e:
                self.pprint(f"{netdata['dictname']} creation failed", "FAIL")
                self.pprint(f"Exception: {e}", "FAIL")
                sys.exit(1)

            # clean old keyfile
            if os.path.exists(self.conf["key_file"]):
                os.unlink(self.conf["key_file"])

            return netdata
        except TypeError as e:
            self.pprint("Couldn't prepare challenge", "FAIL")
            self.pprint(f"Exception: {e}", "FAIL")
            sys.exit(1)

    def put_work(self, cand, hkey=None, idtype="bssid"):
        """return results to server"""
        pw = {"hkey": hkey,
              "type": idtype,
              "cand": cand}
        pwjson = json.dumps(pw).encode("utf-8")

        self.get_url(self.conf["put_work_url"], pwjson)


    def create_resume(self, netdata):
        """create resume file"""
        with open(self.conf["res_file"], "w", encoding="utf-8") as fd:
            json.dump(netdata, fd)

    def resume_check(self):
        """check for resume files"""
        netdata = None
        dictcount = 1
        if os.path.exists(self.conf["res_file"]):
            with open(self.conf["res_file"], "r", encoding="utf-8") as fd:
                try:
                    netdata = json.load(fd)
                    if not "hashes" in netdata or not "hkey" in netdata:
                        raise ValueError
                    if "dicts" in netdata:
                        dictcount = len(netdata["dicts"])
                    self.pprint("Session resume", "OKBLUE")
                except (TypeError, ValueError, KeyError):
                    netdata = None
                    self.pprint("Bad resume file contents", "WARNING")
                    os.unlink(self.conf["res_file"])

        return netdata, dictcount

    def run_cracker(self, dictlist, disablestdout=False):
        """run external cracker process"""
        fd = None
        if disablestdout:
            fd = open(os.devnull, "w") # pylint: disable=consider-using-with,unspecified-encoding

        if os.path.exists(self.conf["hash_file"]):
            if self.conf["format"] == "22000":
                cracker = f"{self.conf['cracker']} -m22000 --advice-disable --logfile-disable --potfile-disable --nonce-error-corrections=8 --session help_crack {self.conf['rules']} {self.conf['coptions']} -o{self.conf['key_file']} {self.conf['hash_file']} "
                cracker += " ".join(dictlist)

                while True:
                    rc = subprocess.call(shlex.split(cracker), stdout=fd)
                    if rc == -2:
                        self.pprint("Thermal watchdog barked", "WARNING")
                        self.sleepy()
                        continue
                    if rc >= 2 or rc == -1:
                        self.pprint(f"hashcat died with code {rc}", "FAIL")
                        sys.exit(1)
                    break

            # TODO: use multiple -w:, when/if availible, see https://github.com/openwall/john/issues/3262
            if self.conf["format"] == "wpapsk":
                dp = "type " if os.name == "nt" else "cat "
                dp += " ".join(dictlist)
                cracker = f"{self.conf['cracker']} {self.conf['coptions']} --stdin --session=help_crack --pot={self.conf['key_file']} {self.conf['hash_file']}"

                with subprocess.Popen(shlex.split(dp), stdout=subprocess.PIPE) as p1:
                    with subprocess.Popen(shlex.split(cracker), stdin=p1.stdout, stdout=fd) as p2:
                        p1.stdout.close()
                        p2.communicate()

        if fd:
            fd.close()

    def get_key(self):
        """read bssid and key pairs from file"""

        def parse_hashcat_output(pot):
            """parse hashcat potfile line"""
            try:
                arr = pot.split(":", 4)
                return {"k": arr[1][:12], "v": bytes(arr[4].rstrip("\r\n"), encoding="utf-8", errors="ignore").hex()}
            except (TypeError, ValueError, KeyError, IndexError):
                pass

            return False

        def parse_jtr(pot):
            """parse JtR potfile line"""

            def jb64decode(jb64):
                """JtR b64 decode"""
                encode_trans = bytearray.maketrans(b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                                   b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                b64 = jb64.translate(encode_trans) + "="

                return binascii.a2b_base64(b64)

            arr = pot.split(":", 1)
            if len(arr) != 2:
                return False

            key = bytes(arr[1].rstrip("\r\n"), encoding="utf-8", errors="ignore").hex()

            # check for handshake results
            arr1 = arr[0].split("#", 1)
            if len(arr1) == 2:
                try:
                    phccap = jb64decode(arr1[1])
                    bssid = phccap[:6].hex()
                    return {"k": bssid, "v": key}
                except (binascii.Error, binascii.Incomplete):
                    return False

            # check for PMKID results
            arr1 = arr[0].split("*", 3)
            if len(arr1) == 4:
                return {"k": arr1[1], "v": key}

            return False

        res = []
        try:
            if os.path.exists(self.conf["key_file"]):
                with open(self.conf["key_file"], "r", encoding="utf-8", errors="ignore") as fd:
                    for line in fd:
                        # check if we have user potfile and don't write if it's the challenge
                        if self.conf["potfile"] and not \
                            ("1c7ee5e2f2d0:0026c72e4900:dlink:aaaa1234" in line or
                             "1c7ee5e2f2d0*0026c72e4900*646c696e6b:aaaa1234" in line or
                             "0OOMSwZsHKYh0C19gHglzE:aaaa1234" in line):
                            with open(self.conf["potfile"], "a", encoding="utf-8") as fdpot:
                                fdpot.write(line)

                        keypair = parse_hashcat_output(line)
                        if keypair:
                            res.append(keypair)
                            continue
                        keypair = parse_jtr(line)
                        if keypair:
                            res.append(keypair)
                            continue

            if res:
                os.unlink(self.conf["key_file"])
                return res
        except IOError as e:
            self.pprint("Couldn't read pot file", "FAIL")
            self.pprint(f"Exception: {e}", "FAIL")
            sys.exit(1)

    def run(self):
        """entry point"""
        self.check_version()
        self.check_tools()

        # challenge the cracker
        self.pprint("Challenge cracker for correct results", "OKBLUE")
        netdata = self.prepare_challenge()
        self.prepare_work(netdata)
        self.run_cracker([netdata["dictname"]], disablestdout=True)
        keypair = self.get_key()

        if not keypair or len(keypair) != 2 or keypair[0]["v"] != keypair[1]["v"] != netdata["key"]:
            self.pprint("Challenge solving failed! Check if your cracker runs correctly.", "FAIL")
            sys.exit(1)

        netdata, dictcount = self.resume_check()
        metadata = {}
        while True:
            if netdata is None:
                netdata = self.get_work(dictcount)

            self.create_resume(netdata)
            metadata = self.prepare_work(netdata)

            # prepare remote dicts
            dictlist = self.prepare_dicts(netdata)
            if dictlist is None:
                netdata = None
                self.pprint("Couldn't prepare dictionaries", "WARNING")
                self.sleepy()
                continue

            # do we have additional user dictionary supplied?
            if self.conf["additional"] is not None:
                if self.conf["additional"] not in dictlist:
                    dictlist.append(self.conf["additional"])

            # run cracker and collect results
            cstart = time.time()
            self.run_cracker(dictlist)
            cdiff = int(time.time() - cstart)

            # check for cracked keys
            keypair = self.get_key()
            if keypair:
                for k in keypair:
                    try:
                        self.pprint(f"Key for bssid {k['k']} is: {bytes.fromhex(k['v']).decode('utf-8')}", "OKGREEN")
                    except UnicodeEncodeError:
                        pass
            self.put_work(keypair, metadata["hkey"])

            # autotune dictionary count
            if dictcount < 15 and cdiff < 300:  # 5 min
                dictcount += 1
                self.pprint(f"Incrementing dictionary count to {dictcount}, last duration {cdiff}s", "OKBLUE")
            if dictcount > 1 and cdiff > 300:
                dictcount -= 1
                self.pprint(f"Decrementing dictionary count to {dictcount}, last duration {cdiff}s", "OKBLUE")

            # cleanup
            if os.path.exists(self.conf["res_file"]):
                os.unlink(self.conf["res_file"])
            netdata = None


def signal_handler(sig, frame): # pylint: disable=unused-argument
    """global signal handler"""
    print("\nCtrl-C caught. I'm out.")
    sys.exit(1)

if __name__ == "__main__":
    # set global signal handler
    signal.signal(signal.SIGINT, signal_handler)

    def is_valid_file(aparser, arg):
        """check if it's a valid file"""
        if not os.path.isfile(arg):
            aparser.error(f"The file {arg} does not exist!")
        return arg

    parser = argparse.ArgumentParser(description=f"help_crack, distributed WPA cracker site: {conf['base_url']}")
    parser.add_argument("-v",   "--version",    action="version", version=conf["hc_ver"])
    parser.add_argument("-co",  "--coptions",   type=str, help="custom options, that will be supplied to cracker. Those must be passed as -co='--your_option'")
    parser.add_argument("-pot", "--potfile",    type=str, help="preserve cracked results in user supplied pot file")
    parser.add_argument("-ad",  "--additional", type=lambda x: is_valid_file(parser, x), help="additional user dictionary to be checked after downloaded one")

    try:
        args = parser.parse_args()
    except IOError as ex:
        parser.error(str(ex))

    conf["additional"] = args.additional
    if args.coptions:
        conf["coptions"] = args.coptions
    if args.potfile and (os.path.basename(args.potfile) not in (conf["res_file"], conf["hash_file"], conf["key_file"])):
        conf["potfile"] = args.potfile

    # set global timeout duration
    socket.setdefaulttimeout(120)

    hc = HelpCrack(conf)
    hc.run()
