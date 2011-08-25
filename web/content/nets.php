<?
require('db.php');
if (empty($_POST)): ?>
<h1>Last 20 submitted networks</h1>
<form class="form" method="POST" action="?nets" enctype="multipart/form-data">
<table style="border: 1;">
<tr><th>BSSID</th><th>SSID</th><th>WPA key</th><th>Timestamp</th></tr>
<?
    $sql = 'SELECT * FROM nets ORDER BY ts DESC LIMIT 20';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $stmt->execute();
    $data = array();
    stmt_bind_assoc($stmt, $data);
    while ($stmt->fetch()) {
        $bssid = str_pad(dechex($data['bssid']), 12, '0', STR_PAD_LEFT);
        $bssid = "{$bssid[0]}{$bssid[1]}:{$bssid[2]}{$bssid[3]}:{$bssid[4]}{$bssid[5]}:{$bssid[6]}{$bssid[7]}:{$bssid[8]}{$bssid[9]}:{$bssid[10]}{$bssid[11]}";
        $ssid = htmlspecialchars($data['ssid']);
        if ($data['pass'] == '') {
            $pass = '<input class="input" type="text" name="'.$bssid.'" size="20"/>';
        } else
            $pass = htmlspecialchars($data['pass']);
        $ts = $data['ts'];
        echo "<tr><td style=\"font:Courier;\">$bssid</td><td>$ssid</td><td>$pass</td><td>$ts</td></tr>\n";
    }
?>
</table>
<input class="submitbutton" type="submit" value="Send WPA keys" />
</form>
<? else:
    require('common.php');

    //Check stmt
    $sql = 'SELECT * FROM nets WHERE bssid = ? AND n_state=0';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $data = array();
    stmt_bind_assoc($stmt, $data);

    //Update key stmt
    $usql = 'UPDATE nets SET pass=?, sip=?, n_state=1, sts=NOW() WHERE bssid=?';
    $ustmt = $mysql->stmt_init();
    $ustmt->prepare($usql);

    foreach ($_POST as $bssid => $key) {
        if (preg_match('/([a-f0-9]{2}:?){6}/', $bssid) && strlen($key) >= 8) {
            $ibssid = hexdec(str_replace(':', '', $bssid));
            $stmt->bind_param('i', $ibssid);
            $stmt->execute();

            if ($stmt->fetch())
                if (check_pass($bssid, $key)) {
                    $stmt->free_result();
                    $iip = ip2long($_SERVER['REMOTE_ADDR']);
                    $ustmt->bind_param('sii', mysqli_real_escape_string($mysql, $key), $iip, $ibssid);
                    $ustmt->execute();
                }
        }
    }
    $ustmt->close();
endif;
$stmt->close();
$mysql->close();
?>
