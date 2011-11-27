<?
require('conf.php');
//Check for submission from besside-ng
if (isset($_FILES['file'])) {
    require('db.php');
    require('common.php');
    if (submission($mysql, $_FILES['file']['tmp_name']))
        echo 2;
    else
        echo 0;
    $mysql->close();
    exit;
}

//User key actions
if (isset($_POST['recaptcha_response_field'])) {
    require_once('recaptchalib.php');
    $recap_resp = recaptcha_check_answer ($privatekey,
                                    $_SERVER['REMOTE_ADDR'],
                                    $_POST['recaptcha_challenge_field'],
                                    $_POST['recaptcha_response_field']);

    if ($recap_resp->is_valid) {
        require_once('db.php');
        require_once('common.php');

        //if we have email, validate it
        $mail = Null;
        if (isset($_POST['mail']))
            if (validEmail($_POST['mail']))
                $mail = trim($_POST['mail']);

        //put new key in db
        $sql = 'INSERT IGNORE INTO users(ukey, mail, ip) VALUES(?, ?, ?)';
        $stmt = $mysql->stmt_init();
        $ip = ip2long($_SERVER['REMOTE_ADDR']);
        $ukey = gen_key();
        $stmt->prepare($sql);
        $stmt->bind_param('ssi', $ukey, $mail, $ip);
        $stmt->execute();
        $stmt->close();

        //set cookie
        setcookie('key', $ukey, 2147483647, '', '', false, true);
        $_COOKIE['key'] = $ukey;
    }
}

//validate 32 char key
function valid_key($key) {
    return preg_match('/^[a-f0-9]{32}$/', strtolower($key));
}

//Set key
if (isset($_POST['key'])) {
    if (valid_key($_POST['key'])) {
        require_once('db.php');
        $sql = 'SELECT ukey FROM users WHERE ukey=?';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        $stmt->bind_param('s', $_POST['key']);
        $stmt->execute();
        $stmt->store_result();
        
        if ($stmt->num_rows == 1) {
            setcookie('key', $_POST['key'], 2147483647, '', '', false, true);
            $_COOKIE['key'] = $_POST['key'];
        } else
            $_POST['remkey'] = '1';
        $stmt->close();
    }
}

//Remove key
if (isset($_POST['remkey'])) {
    setcookie('key', '', 1, '', '', false, true);
    unset($_COOKIE['key']);
}

//CMS
$content = 'content/';
$keys = array('home', 'get_key', 'my_nets', 'submit', 'nets', 'dicts', 'stats', 'search', 'get_work', 'put_work');
$keys_if = array('get_work', 'put_work');

list($key) = each($_GET);
if (!in_array($key,$keys))
	$key = 'home';

if (in_array($key, $keys_if)) {
    require($content.$key.'.php');
    exit;
}

$cont = $content.$key.'.php';
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>

<meta http-equiv="Content-type" content="text/html; charset=UTF-8" />
<meta name="description" content="Distributed WPA PSK security audit environment" />
<meta name="keywords" content="free, audit, security, online, besside-ng, aircrack-ng, pyrit, wpa, wpa2, crack, cracker, distributed, wordlist" />

<title>Distributed WPA PSK strength auditor</title>

<link rel="stylesheet" href="style.css" type="text/css" media="screen" />

</head>
<body>

<a name="top"></a>

<div id="header">Distributed WPA PSK auditor</div>

<ul id="navtop">
<li style="float:right;padding-right: 7px;"><form action="" method="get">Search <input class="searchinput" type="text" id="search" name="search" value="" /></form></li>
<li style="float:right;padding-right: 7px;"><form action="" method="post">Key 
<?
if (isset($_COOKIE['key']))
    echo htmlspecialchars($_COOKIE['key']).' <input type="hidden" id="remkey" name="remkey" value="1" /><input class="keybutton" type="submit" value="X" onclick=\'return confirm("Are you sure you want to dispose the key?")\'/>';
else
    echo '<input class="searchinput" type="text" id="key" name="key" value="" />';
?>
</form></li>
<li><a href="?">Home</a></li>
<li>
<?
if (isset($_COOKIE['key']))
    echo '<a href="?my_nets">My nets</a>';
else
    echo '<a href="?get_key">Get key</a>';
?>
</li>
<li><a href="?submit">Submit</a></li>
<li><a href="?nets">Nets</a></li>
<li><a href="?dicts">Dicts</a></li>
<li><a href="?stats">Stats</a></li>
</ul>
<div id="maincontainer">

<div id="contentwrapper">
<div id="contentcolumn">

<?@include($cont)?>

</div>
</div>

<div id="footer">
<div class="hr"><hr /></div>
Contact: alex at stanev dot org
</div>

</div>
</body>
</html>
