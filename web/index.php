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
if ($_POST['recaptcha_response_field']) {
    require('recaptchalib.php');
    $recap_resp = recaptcha_check_answer ($privatekey,
                                    $_SERVER['REMOTE_ADDR'],
                                    $_POST['recaptcha_challenge_field'],
                                    $_POST['recaptcha_response_field']);

    if ($recap_resp->is_valid) {
        require('db.php');
        require('common.php');

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

//CMS
$content = 'content/';
$keys = array('home', 'get_key', 'submit', 'nets', 'dicts', 'stats', 'search', 'get_work', 'put_work');
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
<meta name="description" content="besside-ng wpa crack" />
<meta name="keywords" content="besside-ng, wpa, crack, wordlist" />

<title>Free online WPA cracker with stats - besside-ng companion</title>

<link rel="stylesheet" href="style.css" type="text/css" media="screen" />

</head>
<body>

<a name="top"></a>

<div id="header">Free online WPA cracker</div>

<ul id="navtop">
<li style="float:right;padding-right: 7px;"><form action="" method="get">Search <input class="searchinput" type="text" id="search" name="search" value="" /></form></li>
<li style="float:right;padding-right: 7px;"><form action="" method="post">Key 
<?
if ($_COOKIE['key'])
    echo htmlspecialchars($_COOKIE['key']);
else
    echo '<input class="searchinput" type="text" id="key" name="key" value="" />';
?>
</form></li>
<li><a href="?">Home</a></li>
<li><a href="?get_key">Get key</a></li>
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
Contact: sorbo at darkircop dot org
</div>

</div>
</body>
</html>
