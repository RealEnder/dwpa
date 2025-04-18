<?php
require "../conf.php";
// Check for direct submission from besside-ng
if (isset($_FILES["file"])) {
    require "../db.php";
    require "../common.php";
    $status = @submission($mysql, $_FILES["file"]["tmp_name"]);
    $mysql->close();
    echo $status;
    die();
}

// User key actions
$rec_valid = false;
$mess = false;
if (isset($_POST["g-recaptcha-response"])) {
    // check reCAPTCHA
    $opts = [
        "http" => [
            "method" => "POST",
            "header" => [
                "Content-Type: application/x-www-form-urlencoded",
                "User-Agent: wpa-sec",
            ],
            "content" => http_build_query([
                "secret" => $privatekey,
                "response" => $_POST["g-recaptcha-response"],
                "remoteip" => $_SERVER["REMOTE_ADDR"],
            ]),
        ],
    ];
    $context = stream_context_create($opts);
    $response = file_get_contents(
        "https://www.google.com/recaptcha/api/siteverify",
        false,
        $context
    );

    // validate reCAPTCHA response
    $responseData = json_decode($response, true);
    if (isset($responseData["success"]) && $responseData["success"] == true) {
        $rec_valid = true;
    }

    if ($rec_valid) {
        require_once "../db.php";
        require_once "../common.php";

        // validate e-mail
        $mail = false;
        if (isset($_POST["mail"]) && validEmail(trim($_POST["mail"]))) {
            $mail = trim($_POST["mail"]);
        }

        if ($mail) {
            // put new key in db and send confirmation mail
            // TODO: fix this workaround properly
            mysqli_report(MYSQLI_REPORT_OFF);
            $sql =
                "INSERT INTO users(userkey, linkkey, mail, ip) VALUES(UNHEX(?), UNHEX(?), ?, ?)";
            $stmt = $mysql->stmt_init();
            $ip = ip2long($_SERVER["REMOTE_ADDR"]);
            $key = gen_key();
            $stmt->prepare($sql);
            $stmt->bind_param("sssi", $key, $key, $mail, $ip);
            $res = $stmt->execute();
            $stmt->close();
            mysqli_report(MYSQLI_REPORT_ALL);

            // if we succeeded the insert
            if ($res) {
                // set cookie
                setcookie("key", $key, 2147483647, "", "", false, true);
                $_COOKIE["key"] = $key;

                // send mail with the key
                require_once "../mail.php";
                try {
                    $mailer->AddAddress($mail);
                    $mailer->Subject = "{$_SERVER["HTTP_HOST"]} key";
                    $mailer->Body = "Key to access results is: $key";
                    $mailer->Send();
                    $mailer->SmtpClose();
                } catch (Exception $e) {
                }
                $mess =
                    "User key issued. Make sure you keep it to access the results.";
            } else {
                // send key reset confirmation e-mail - once in 24h
                $sql =
                    "UPDATE users SET linkkey = UNHEX(?), linkkeyts = CURRENT_TIMESTAMP() WHERE mail = ? AND DATE_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY) > linkkeyts";
                $stmt = $mysql->stmt_init();
                $stmt->prepare($sql);
                $stmt->bind_param("ss", $key, $mail);
                $res = $stmt->execute();
                $uc = $stmt->affected_rows;
                $stmt->close();

                // if update passed, send mail, else user should wait 24h
                if ($uc == 1) {
                    require_once "../mail.php";
                    try {
                        $mailer->AddAddress($mail);
                        $mailer->Subject = "{$_SERVER["HTTP_HOST"]} key change";
                        $mailer->Body = "A request for a new user key was submitted. Please follow this link to confirm: {$_SERVER["REQUEST_SCHEME"]}://{$_SERVER["HTTP_HOST"]}/?get_key=$key";
                        $mailer->Send();
                        $mailer->SmtpClose();
                    } catch (Exception $e) {
                    }
                    $mess =
                        "New key request was submitted. Please check you e-mail to confirm.";
                } else {
                    $mess =
                        "User key request was already submitted. Please try again tomorrow.";
                }
            }
        }
    }
}

// Validate 32 char key
function valid_key($key)
{
    return preg_match('/^[a-f0-9]{32}$/', strtolower($key));
}

// Set key
if (isset($_POST["key"]) && valid_key($_POST["key"])) {
    if ($_POST["key"] === $bosskey) {
        setcookie("key", $_POST["key"], 2147483647, "", "", false, true);
    } else {
        require_once "../db.php";
        $sql = "SELECT u_id FROM users WHERE userkey=UNHEX(?)";
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        $stmt->bind_param("s", $_POST["key"]);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows == 1) {
            setcookie("key", $_POST["key"], 2147483647, "", "", false, true);
            $_COOKIE["key"] = $_POST["key"];
        } else {
            $_POST["remkey"] = "1";
        }
        $stmt->close();
    }

    header("Location: /");
    die();
}

// Remove key
if (isset($_POST["remkey"])) {
    setcookie("key", "", 1, "", "", false, true);
    unset($_COOKIE["key"]);
}

// CMS
$content = "../content/";
$keys = [
    "home",
    "get_key",
    "get_work_API",
    "my_nets",
    "submit",
    "nets",
    "dicts",
    "prdict",
    "stats",
    "search",
    "get_work",
    "put_work",
    "api",
];
$keys_if = ["get_work", "put_work", "api", "get_work_API", "prdict"];

if (count($_GET) > 0) {
    $key = array_keys($_GET)[0];
} else {
    $key = [];
}
if (!in_array($key, $keys)) {
    $key = "home";
}

$cont = $content . $key . ".php";

if (in_array($key, $keys_if)) {
    require $cont;
    exit();
}
?>
<!DOCTYPE html>
<html lang="en" xml:lang="en">
<head>

<meta http-equiv="Content-type" content="text/html; charset=utf-8">
<meta name="description" content="Distributed WPA PSK security audit environment">
<meta name="keywords" content="free, audit, security, online, hcxtools, hcxpcapngtool, hcxdumptool, hashcat, john, jtr, besside-ng, aircrack-ng, pyrit, wpa, wpa2, crack, cracker, distributed, wordlist">

<title>Distributed WPA PSK strength auditor</title>

<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.3.2/css/flag-icons.min.css">
<link rel="stylesheet" href="style.css" type="text/css" media="screen">

</head>
<body>

<a id="top"></a>

<div id="header">Distributed WPA PSK auditor</div>

<ul id="navtop">
<li style="float:right;padding-right: 7px;"><form method="get">Search <input class="searchinput" type="text" id="search" name="search" value=""></form></li>
<li style="float:right;padding-right: 7px;"><form method="post">Key
<?php if (isset($_COOKIE["key"])) {
    echo htmlspecialchars($_COOKIE["key"]) .
        ' <input type="hidden" id="remkey" name="remkey" value="1" /><input class="keybutton" type="submit" value="X" onclick=\'return confirm("Are you sure you want to dispose the key?")\'>';
} else {
    echo '<input class="searchinput" type="text" id="key" name="key" value="">';
} ?>
</form></li>
<li><a href="?">Home</a></li>
<li>
<?php if (isset($_COOKIE["key"])) {
    echo '<a href="?my_nets">My nets</a>';
} else {
    echo '<a href="?get_key">Get key</a>';
} ?>
</li>
<li><a href="?submit">Submit</a></li>
<li><a href="?nets">Nets</a></li>
<li><a href="?dicts">Dicts</a></li>
<li><a href="?stats">Stats</a></li>
</ul>
<div id="maincontainer">

<div id="contentwrapper">
<div id="contentcolumn">

<?php @include $cont; ?>

</div>
</div>

<div id="footer">
    <div class="hr"><hr></div>
    Contact: alex at stanev dot org X:<a href="https://x.com/RealEnderSec">@RealEnderSec</a>
</div>

</div>
</body>
</html>
