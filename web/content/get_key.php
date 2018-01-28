<h1>Get key</h1>
<p>
<?php
if ($rec_valid) {
    echo 'Key issued. Make sure you keep it to access the results.';
} else {
    if (isset($_COOKIE['key']))
        echo 'Key already issued.';
    else {
        echo '
Key is needed to see results for your uploaded handshakes. You may use one key with multiple uploads.<br/>
If you provided a valid e-mail and lost the key, new key will be assocciated with your previous submissions. This is not a mandatory field.<br/>
When issued, the key will appear next to the search box and you can proceed with <a href="?submit">captures upload</a>.
<script src="https://www.google.com/recaptcha/api.js"></script>
<form class="form" action="" method="post">
E-mail: <input class="searchinput" type="text" id="mail" name="mail" value="" />
<br/><br/>
<div class="g-recaptcha" data-sitekey="';
echo $publickey;
echo '"></div>
<br/><br/>
<input class="submitbutton" type="submit" value="Get private key" />
</form>
';
    }
}
?>
</p>
