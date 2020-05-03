<?php
// DB Configuration
$cfg_db_host = 'db';
$cfg_db_user = 'wpa';
$cfg_db_pass = 'wpapass';
$cfg_db_name = 'wpa';

// reCaptcha auth
$publickey  = '';
$privatekey = '';

// Bosskey
$bosskey = '';

// 3wifi API key
$wifi3apikey = '';

// wigle API key
$wigleapikey = '';

// App specific defines
define('HCXPCAPTOOL', '/tools/bin/hcxpcaptool');
define('RKG', '/tools/bin/routerkeygen-cli');

define('CAP', '/var/www/html/cap/');
define('CRACKED', '/var/www/html/dict/cracked.txt.gz');
if (is_dir('/run/shm'))
    define('SHM', '/run/shm/');
elseif (is_dir('/dev/shm'))
    define('SHM', '/dev/shm/');
else
    die('Can not access SHM!');

define('MIN_HC_VER', '1.1.0');
?>
