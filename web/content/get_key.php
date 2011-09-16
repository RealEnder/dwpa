<h1>Get key</h1>
<?
if ($recap_resp->is_valid) {
    require('db.php');

    $stats = array();
    $sql = 'SELECT * FROM stats';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $data = array();
    stmt_bind_assoc($stmt, $data);
    $stmt->execute();

    while ($stmt->fetch())
        $stats[$data['pname']] = $data['pvalue'];
    $stmt->close();
    $mysql->close();

    echo "Total nets: {$stats['nets']}<br/>\n";
    echo "Cracked nets: {$stats['cracked']}<br/>\n";
    if ((int) $stats['nets'] > 0) {
        $srate = round((int) $stats['cracked'] / (int) $stats['nets'] * 100, 2);
        echo "Success rate: $srate %<br/>\n";
    }
} else {
    require_once('recaptchalib.php');
    echo '
Key is needed to see results for your uploaded captures. You may use one key with multiple uploads.<br/>
If you provide valid e-mail, results will be mailed when avaible (currently disabled). This is not a mandatory field.<br/>
<script type="text/javascript">
    var RecaptchaOptions = {theme: "white"};
</script>
<form class="form" action="" method="post">';
 
    echo recaptcha_get_html($publickey, $recap_resp->error);

    echo'
<br/>
<input class="submitbutton" type="submit" value="Get private key" />
</form>';
}
?>
