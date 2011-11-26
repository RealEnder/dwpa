#!/usr/bin/python
# The source code is distributed under GPLv3+ license
import urllib
import urllib2
import re
import gzip
import MultipartPostHandler
from lxml import html

# Full list url: http://wpa.darkircop.org/index.php?off=0&limit=-1
darkircop     = 'http://wpa.darkircop.org/index.php?off=0&limit=-1'
darkircop_cap = 'http://wpa.darkircop.org/cap/wpa.cap.gz'
base_url      = 'http://wpa-sec.stanev.org/'
put_work_url  = base_url + '?put_work'
put_cap_url   = base_url + '?submit'

def get_url(url):
    try:
        response = urllib.urlopen(url)
    except Exception, e:
        return False
    remote = response.read()
    response.close()
    return remote.strip()

def download(url, filename):
    try:
        urllib.urlretrieve(url, filename)
    except Exception as e:
        print 'Exception: %s' % e
        return False

    return True

def decomp(gzname):
    name = gzname.rsplit('.', 1)[0]
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

    return name

def valid_mac(mac):
    if len(mac) != 17:
        return False
    if not re.match(r'^([a-f0-9]{2}\:?){6}$', mac):
        return False
    return True

def put_work(bssid, key):
    data = urllib.urlencode({bssid: key})
    try:
        response = urllib.urlopen(put_work_url, data)
    except:
        return False

    remote = response.read()
    response.close()

    if remote != 'OK':
        return False

    return True

print 'Import nets and pass from wpa.darkircop.org, v0.3'

print 'Downloading wpa.cap.gz...'
download(darkircop_cap, 'wpa.cap.gz')
if not decomp('wpa.cap.gz'):
    exit(1)

print 'Submitting wpa.cap...'
params = {'webfile':open('wpa.cap', 'rb')}
opener = urllib2.build_opener(MultipartPostHandler.MultipartPostHandler)
urllib2.install_opener(opener)
req = urllib2.Request(put_cap_url, params)
response = urllib2.urlopen(req).read().strip()

print 'Getting nets and keys...'
page = get_url(darkircop)

print 'Submitting nets and keys...'
doc = html.fromstring(page)
i = 0
for data in doc.xpath('//tr'):
    #print data
    key = data.xpath('.//td[4]/text()')
    if len(key) == 0:
        continue
    key = key[0].strip()
    bssid = data.xpath('.//td[10]/textarea/@name')
    bssid = bssid[0].replace('comment-', '')
    bssid = bssid.replace('-', ':')
    bssid = bssid.strip()

    if len(key) >= 8 and valid_mac(bssid):
        i += 1
        print i, 'Pair found: BSSID: '+bssid+' Key: '+ key
        if not put_work(bssid, key):
            print 'Pair send failed'
    else:
        print 'Small len or not valid mac!'
