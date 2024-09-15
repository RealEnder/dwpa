Distributed WPA PSK auditor install guide
=

These are the basic steps for local installation of the distributed WPA PSK auditor. Installation process is not automated and requires some basic Linux knowledge. Please follow the steps as close as possible.

Requirements
-

 - 64bit Linux OS - tested with Ubuntu 22.04 64bit
 - MySQL database 8.0 or better
 - PHP 8.1 or better.
 - Apache or other webserver with PHP support, vhost configured with https
 - gcc toolchain
 - hcxpcapngtool tool (min version 6.3.4), part of hcxtools https://github.com/ZerBea/hcxtools
 - git `sudo apt-get install git`
 - reCAPTCHA API keys for your domain, register here https://www.google.com/recaptcha
 - routerkeygen-cli, part of routerkeygenPC, https://github.com/routerkeygen/routerkeygenPC
 - (optional) Wigle API key, for geolocation, https://wigle.net
 - (optional) 3wifi API key, for already found PSKs, https://3wifi.stascorp.com (currently defunct, don't use)

Compilation of external tools
-

- hcxpcaptool
```
$ git clone https://github.com/ZerBea/hcxtools
$ cd hcxtools
$ make
```
Your binary should be `hcxpcapngtool`.

- routerkeygenPC
Install qt5 development environment.
```
$ git clone https://github.com/routerkeygen/routerkeygenPC
$ cd routerkeygenPC/cli
$ qmake
$ make
```
Your binary should be `routerkeygen-cli`.

Crontab
-

Create crontab entries for running synchronous jobs:

| Script | Interval | Description |
| ------ | ------- | ----------- |
| `maint.php` | 1 hour | Computes statistics, regenerates cracked.txt, cleanup DB |
| `rkg.php` | 5 min | Runs `routerkeygnen-cli` over converted hashes. This is required to release hashes for cracking to volunteers, running `help_crack.py` |
| `wigle.php` | 10 min | Retrieves BSSID geolocation of APs by BSSID |
| `3wifi.php` | 10 min | Lookup candidates through 3wifi API. Currently defunct |

 Example crontab entry for those can be found in [misc](/misc) directory.

Database
-

- Create new MySQL database, eg. `wpa` and user with access to it
```
mysql> create database wpa collate utf8_general_ci;
Query OK, 1 row affected (0.00 sec)

mysql> grant all privileges on wpa.* to 'wpa'@'localhost' identified by "wpapass";
Query OK, 0 rows affected (0.10 sec)

mysql> flush privileges;
Query OK, 0 rows affected (0.09 sec)
```
- Create tables, views and events. Use files from [db](/db) in dwpa repo
```
$ cd db
$ mysql -u wpa -p wpa < wpa.sql
Enter password:
$ mysql -u wpa -p wpa < wpa-data.sql
Enter password:
$
```

Dictionaries
-

Your dictionaries have to conform requirements for WPA PSK - every password candidate have to be between 8 and 63 bytes long. All dictionaries have to be text files with .txt extension, one password candidate per line.
There is one special dictionary - cracked.txt. This one will contain already cracked PSKs. The dictionary will be autocreated by the script below.
You will need to know the URL of directory, under where your dictionaries will be accessed by clients, eg. `https://[example.com]/dict/`.
Start with copying all your dictionaries in separate directory. Then copy in it the preparation script `misc/create_gz.sh` from dwpa repo and execute it:
```
$ ls
create_gz.sh  dict1.txt  dict2.txt
$ ./create_gz.sh
Compress dictionaries(*.txt) in current dir and create inserts for dwpa
Enter base URL for dict with trailing /: https://example.com/dict/
INSERT INTO dicts (dpath, dhash, dname, rules, wcount, hits) VALUES ('https://example.com/dict/cracked.txt.gz', X'f54e2d10d5f790295c3401f8074df51f', 'cracked', ':', 1, 0);
INSERT INTO dicts (dpath, dhash, dname, rules, wcount, hits) VALUES ('https://example.com/dict/dict1.txt.gz', X'17e5a375da3670754bf40657a1fc5876', 'dict1', ':', 1, 0);
INSERT INTO dicts (dpath, dhash, dname, rules, wcount, hits) VALUES ('https://example.com/dict/dict2.txt.gz', X'bd189d3f58169dc7bf58427d273d95c5', 'dict2', ':', 2, 0);
$ ls
cracked.txt     create_gz.sh  dict1.txt.gz  dict2.txt.gz
cracked.txt.gz  dict1.txt     dict2.txt     dict.sql
$
```
This will create cracked.txt (if needed), compress dictionaries and generate insert scripts (on screen and in dict.sql). Copy all compressed dicts (*.gz) to your server under previously specified location and execute insert script:
```
$ mysql -u wpa -p wpa < dict.sql
Enter password:
$
```
> **Note:**
> Check out [misc/dedup.sh](/misc/dedup.sh) script to preprocess your dictionaries - for deduplication and sorting.

The column `rules` in `dicts` table contains custom per-dictionary rules in hashcat format, which will be combined and sent to the crackers. By default leave the no-op ":" rule there. Add rules depending on dictionary contents. More information on rule syntax [here](https://hashcat.net/wiki/doku.php?id=rule_based_attack).

Web application configuration
-
- Copy all files from `web` directory from dwpa repo to your webserver root
- Copy previously built `hcxpcapngtool` binary to a location, where web server process can execute it, eg. in webserver root
- edit `mail.php` and put your own SMTP configuration
- Make sure webserver process can write to dictionaries location (to update cracked.txt.gz) and capture file location(`CAP` define from conf.php), where submissions will be written
- `bosskey` must be 32 byte hexadecimal string, known to you, with which you will be able to see cracked PSKs in clear and search the full database

Assuming:

- your webserver root vhost location is `/var/www/wpa-sec`
- your cap files location is `/var/www/wpa-sec/cap`
- your dictionaries location is `/var/www/wpa-sec/dict`

conf.php should look something like this:

```
<?php
// DB Configuration
$cfg_db_host = 'localhost';
$cfg_db_user = 'wpa';
$cfg_db_pass = 'wpapass';
$cfg_db_name = 'wpa';

// reCaptcha auth
$publickey = '<your reCAPTCHA public key>';
$privatekey = '<your reCAPTCHA private key>';

//bosskey
$bosskey = '01234567890123456789012345678901';

// 3wifi API key
$wifi3apikey = '<your 3wifi API key>';

// wigle API key
$wigleapikey = '<your wigle API key>';

// App specific defines
define('HCXPCAPTOOL', '/var/www/wpa-sec/cap/hcxpcaptool');
define('RKG', '/var/www/wpa-sec/cap/routerkeygen-cli');

define('CAP', '/var/www/wpa-sec/cap/');
define('CRACKED', '/var/www/wpa-sec/dict/cracked.txt.gz');

define('SHM', '/tmp/');
define('MIN_HC_VER', '2.0.0');
?>
```

Client application configuration
-

Your clients will run `help_crack.py` to fetch uncracked nets and dictionaries. You'll need to do the following changes:

- Copy `help_crack.py`, `help_crack.py.version` and `CHANGELOG` files from `dwpa` repo under `hc/` directory of your webserver root
- Change `base_url` variable from `help_crack.py` to point to your server URL, eg. `base_url = 'https://example.com/'`, with trailing /

Migration to m22000 storage
-

- Run `misc/migrate_to_m22000.php` from wpa-sec webroot. The DB user have to have SUPER privileges temporary, after the script finishes, you can revoke them.
- Update the php code.
- Run `misc/enrich_pmkid.php` from wpa-sec webroot. This will update PMKID hashlines and will fill message_pair column.
