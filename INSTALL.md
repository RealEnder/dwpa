Distributed WPA PSK auditor install guide
=

Those are the basic steps for local installation of the distributed WPA PSK auditor. Installation process is not automated and requires some basic Linux knowledge. Please follow the steps as close as possible.

Requirements
-

 - 64bit Linux OS - tested with Ubuntu 20.04 64bit
 - MySQL database 5.5 or better
 - PHP 7 or better.
 - Apache or other webserver with PHP support, vhost configured with https
 - gcc toolchain
 - hcxpcapngtool tool (min version 6.2), part of hcxtools https://github.com/ZerBea/hcxtools
 - git `sudo apt-get install git`
 - reCAPTCHA API keys for your domain, register here https://www.google.com/recaptcha
 - routerkeygen-cli, part of routerkeygenPC, https://github.com/routerkeygen/routerkeygenPC
 - (optional) Wigle API key, for geolocation, https://wigle.net
 - (optional) 3wifi API key, for already found PSKs, https://3wifi.stascorp.com

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

Create crontab entries for running `rkg.php`, `3wifi.php` and `wigle.php`. Example crontab entry for those can be found in `misc/` directory.

Database
-

 - Enable MySQL events scheduler - this will be needed for statistics update

Create file `/etc/mysql/conf.d/mysqld_events.cnf` with contents:
```
[mysqld]
event_scheduler=ON
```
Restart MySQL daemon to enable the new configuration.

- Create new MySQL database, eg. `wpa` and user with access to it
```
mysql> create database wpa collate utf8_general_ci;
Query OK, 1 row affected (0.00 sec)

mysql> grant all privileges on wpa.* to 'wpa'@'localhost' identified by "wpapass";
Query OK, 0 rows affected (0.10 sec)

mysql> flush privileges;
Query OK, 0 rows affected (0.09 sec)
```
- Create tables, views and events. Use files from `db/` in dwpa repo
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
INSERT INTO dicts (dpath, dhash, dname, wcount, hits) VALUES ('https://example.com/dict/cracked.txt.gz', X'f54e2d10d5f790295c3401f8074df51f', 'cracked', 1, 0);
INSERT INTO dicts (dpath, dhash, dname, wcount, hits) VALUES ('https://example.com/dict/dict1.txt.gz', X'17e5a375da3670754bf40657a1fc5876', 'dict1', 1, 0);
INSERT INTO dicts (dpath, dhash, dname, wcount, hits) VALUES ('https://example.com/dict/dict2.txt.gz', X'bd189d3f58169dc7bf58427d273d95c5', 'dict2', 2, 0);
$ ls
cracked.txt     create_gz.sh  dict1.txt.gz  dict2.txt.gz
cracked.txt.gz  dict1.txt     dict2.txt     dict.sql
$
```
This will create cracked.txt (if needed), compress dictionaries and generate insert scripts (on screen and in dict.sql). Copy all compressed dicts (*.gz) to your server under previously specified location and execute inset script:
```
$ mysql -u wpa -p wpa < dict.sql
Enter password:
$
```
> **Note:**
> Check out `misc/dedup.sh` script to preprocess you dictionaries - for deduplication and sorting.

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
if (is_dir('/run/shm'))
    define('SHM', '/run/shm/');
elseif (is_dir('/dev/shm'))
    define('SHM', '/dev/shm/');
else
    die('Can not access SHM!');
define('MIN_HC_VER', '1.1.0');
?>
```

Client application configuration
-

Your clients will run `help_crack.py` to fetch uncracked nets and dictionaries. You'll need to do the following changes:

- Copy `help_crack.py`, `help_crack.py.version` and `CHANGELOG` files from `dwpa` repo under `hc/` directory of your webserver root
- Change `base_url` variable from `help_crack.py` to point to your server URL, eg. `base_url = 'https://example.com/'`, with trailing /

## Run
```bash
# python help_crack.py
```
If you encounter an error about hashcat hash mode being deprecated, simply append `-co="--deprecated-check-disable"` to the command.
```bash
# python help_crack.py -co="--deprecated-check-disable"
```
