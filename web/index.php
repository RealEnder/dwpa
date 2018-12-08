<?php
require('conf.php');
// Check for direct submission from besside-ng
if (isset($_FILES['file'])) {
    require('db.php');
    require('common.php');
    @submission($mysql, $_FILES['file']['tmp_name']);
    $mysql->close();
    exit('2');
}

// User key actions
$rec_valid = False;
if (isset($_POST['g-recaptcha-response'])) {
    // check reCAPTCHA
    $handle = curl_init('https://www.google.com/recaptcha/api/siteverify');
    $options = array(
        CURLOPT_POST => True,
        CURLOPT_POSTFIELDS => http_build_query(array(
            'secret' => $privatekey,
            'response' => $_POST['g-recaptcha-response'],
            'remoteip' => $_SERVER['REMOTE_ADDR']
        )),
        CURLOPT_HTTPHEADER => array(
            'Content-Type: application/x-www-form-urlencoded'
        ),
        CURLINFO_HEADER_OUT => False,
        CURLOPT_HEADER => False,
        CURLOPT_RETURNTRANSFER => True,
        CURLOPT_SSL_VERIFYPEER => True
    );
    curl_setopt_array($handle, $options);
    $response = curl_exec($handle);
    curl_close($handle);

    // validate reCAPTCHA response
    $responseData = json_decode($response, True);
    if (isset($responseData['success']) && $responseData['success'] == True) {
        $rec_valid = True;
    }

    if ($rec_valid) {
        require_once('db.php');
        require_once('common.php');

        // if we have email, validate it
        $mail = Null;
        if (isset($_POST['mail']) && validEmail($_POST['mail'])) {
            $mail = trim($_POST['mail']);
        }

        // put new key in db
        $sql = 'INSERT INTO users(userkey, mail, ip) VALUES(UNHEX(?), ?, ?)
                ON DUPLICATE KEY UPDATE userkey=UNHEX(?), ip=?, ts=CURRENT_TIMESTAMP()';
        $stmt = $mysql->stmt_init();
        $ip = ip2long($_SERVER['REMOTE_ADDR']);
        $userkey = gen_key();
        $stmt->prepare($sql);
        $stmt->bind_param('ssisi', $userkey, $mail, $ip, $userkey, $ip);
        $stmt->execute();
        $stmt->close();

        // set cookie
        setcookie('key', $userkey, 2147483647, '', '', False, True);
        $_COOKIE['key'] = $userkey;

        // send mail with the key
        if (isset($mail)) {
            require_once('mail.php');
            try {
                $mailer->AddAddress($mail);
		        $mailer->Subject = 'wpa-sec.stanev.org key';
		        $mailer->Body    = "Key to access results is: $userkey";
		        $mailer->Send();
		        $mailer->SmtpClose();
		    } catch (Exception $e) { }
        }
    }
}

// Validate 32 char key
function valid_key($key) {
    return preg_match('/^[a-f0-9]{32}$/', strtolower($key));
}

// Set key
if (isset($_POST['key']) && valid_key($_POST['key'])) {
    require_once('db.php');
    $sql = 'SELECT u_id FROM users WHERE userkey=UNHEX(?)';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $stmt->bind_param('s', $_POST['key']);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows == 1) {
        setcookie('key', $_POST['key'], 2147483647, '', '', False, True);
        $_COOKIE['key'] = $_POST['key'];
    } else
        $_POST['remkey'] = '1';
    $stmt->close();
}

// Remove key
if (isset($_POST['remkey'])) {
    setcookie('key', '', 1, '', '', False, True);
    unset($_COOKIE['key']);
}

// CMS
$content = 'content/';
$keys = array('home', 'get_key', 'my_nets', 'submit', 'nets', 'dicts', 'stats', 'search', 'get_work', 'put_work');
$keys_if = array('get_work', 'put_work');

list($key) = each($_GET);
if (!in_array($key, $keys)) {
	$key = 'home';
}

$cont = $content.$key.'.php';

if (in_array($key, $keys_if)) {
    require($cont);
    exit;
}
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
<?php
if (isset($_COOKIE['key']))
    echo htmlspecialchars($_COOKIE['key']).' <input type="hidden" id="remkey" name="remkey" value="1" /><input class="keybutton" type="submit" value="X" onclick=\'return confirm("Are you sure you want to dispose the key?")\'/>';
else
    echo '<input class="searchinput" type="text" id="key" name="key" value="" />';
?>
</form></li>
<li><a href="?">Home</a></li>
<li>
<?php
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

<?php @include($cont) ?>

</div>
</div>

<div id="footer">
<div class="hr"><hr /></div>
Contact: alex at stanev dot org
</div>

</div>
</body>
</html>
