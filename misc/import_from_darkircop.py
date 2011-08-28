#!/usr/bin/python
# The source code is distributed under GPLv3+ license
import urllib
import re
from lxml import html

# Full list url: http://wpa.darkircop.org/index.php?off=0&limit=-1
darkircop    = 'http://wpa.darkircop.org/index.php?off=0&limit=-1'
base_url     = 'http://wpa-sec.stanev.org/'
put_work_url = base_url + '?put_work'

def get_url(url):
    try:
        response = urllib.urlopen(url)
    except Exception, e:
        return False
    remote = response.read()
    response.close()
    return remote.strip()

def valid_mac(mac):
    if len(mac) != 17:
        return False
    if not re.match(r'([a-f0-9]{2}:?){6}', mac):
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

print 'import nets and pass from wpa.darkircop.org, v0.1.1'

page = get_url(darkircop)
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
    i += 1
    print i, 'Pair found: BSSID: '+bssid+' Key: '+ key

    if len(key) >= 8 and valid_mac(bssid):
        if not put_work(bssid, key):
            print 'Pair send failed'
    else:
        print 'Small len or not valid mac!'
