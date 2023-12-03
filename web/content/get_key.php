<h1>Get key</h1>
<p>
<?php
if ($rec_valid) {
    if ($mail) {
        echo $mess;
    } else {
        echo 'No valid e-mail provided!';
    }
} else {
    if (isset($_GET['get_key']) && valid_key($_GET['get_key'])) {
        require_once('db.php');
        require_once('common.php');

        $sql = 'UPDATE users SET userkey = linkkey WHERE linkkey = UNHEX(?)';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        $stmt->bind_param('s', $_GET['get_key']);
        $res = $stmt->execute();
        $uc = $stmt->affected_rows;
        $stmt->close();

        if ($uc == 1) {
            setcookie('key', $_GET['get_key'], 2147483647, '', '', False, True);
            $_COOKIE['key'] = $_GET['get_key'];
            header('Location: /');

            echo 'User key confirmed.';
        } else {
            echo 'User key NOT set.';
        }
    } elseif (isset($_COOKIE['key']))
        echo 'Key already issued.';
    else {
        echo '
Key is needed to see results for your uploaded handshakes. You may use one key with multiple uploads.<br/>
You must provide a valid e-mail, where validation link will be sent. If the key is lost, a new one can be issued to the same e-mail and you will retain your previous submissions.<br/>
When issued, the key will appear next to the search box and you can proceed with <a href="?submit">captures upload</a>.
<script src="https://www.google.com/recaptcha/api.js"></script>
<form class="form" action="" method="post">
E-mail: <input class="searchinput" type="text" id="mail" name="mail" value="" />
<br/><br/>
<div class="g-recaptcha" data-sitekey="';
        echo $publickey;
        echo '"></div>
<br/><br/>
<input class="btn" type="submit" value="Get private key" />
</form>
';
    }
}
?>
</p>
