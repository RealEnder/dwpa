<?
//DB Configuration
$cfg_db_host='';
$cfg_db_user='';
$cfg_db_pass='';
$cfg_db_name='';

//reCaptcha auth
$publickey = '';
$privatekey = '';

//bosskey
$bosskey = '';

//App specific defines
define('AIRCRACK', 'aircrack-ng');
define('PYRIT', 'pyrit');
define('TCPDUMP', '/usr/sbin/tcpdump');
define('WPACLEAN', '/var/www/wpa-sec/cap/wpaclean');
define('CAP2HCCAP', '/var/www/wpa-sec/cap/cap2hccap');

define('CAP', '/var/www/wpa-sec/cap/');
define('MD5CAPS', '/var/www/wpa-sec/md5caps/');
define('CRACKED', '/var/www/wpa-sec/dict/cracked.txt.gz');
if (is_dir('/run/shm'))
    define('SHM', '/run/shm/');
elseif (is_dir('/dev/shm'))
    define('SHM', '/dev/shm/');
else
    die('Can not access SHM!');

define('MIN_HC_VER', '0.8');
?>
