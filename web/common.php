<?
define('AIRCRACK', 'aircrack-ng');
define('WPACLEAN', '/var/www/wpa-sec/cap/wpaclean');
define('WPA_CAP', '/var/www/wpa-sec/cap/wpa.cap');
define('CAP', '/var/www/wpa-sec/cap/');

//Execute aircrack-ng and check for solved net
function check_pass($bssid, $pass) {
    $wl = '/tmp/wl';
    $kf = '/tmp/key';

    if (strlen($pass) < 8)
        return false;

    @unlink($kf);
    file_put_contents($wl, $pass."\n");

    $x = AIRCRACK." -b $bssid -w $wl -l $kf ".WPA_CAP;
    exec($x);

    $p = @file_get_contents($kf);

    return ($p == $pass);
}

//Process submission
function submission($mysql, $file) {
    $filtercap = $file.'filter';

    // Clean and merge WPA captures
    $res = '';
    $rc = 0;
    exec(WPACLEAN." $filtercap ".WPA_CAP." $file", $res, $rc);
    if ($rc == 0) {
        // Check if we have any new networks
        $sql = 'INSERT IGNORE INTO nets(bssid, ssid, ip) VALUES(?, ?, ?)';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);

        $newcap = false;
        foreach ($res as $net) {
            if (!$newcap)
                if (strpos($net, $file) !== false) {
                    $newcap = true;
                    continue;
                } else
                    continue;
            if (strlen($net) > 22) {
                //check in db
                $mac = mac2long(substr($net, 4, 17));
                $nname = mysqli_real_escape_string($mysql, substr($net, 22));
                $ip = ip2long($_SERVER['REMOTE_ADDR']);
                $stmt->bind_param('isi', $mac, $nname, $ip );
                $stmt->execute();
            }
        }
        $stmt->close();
        rename($filtercap, WPA_CAP);
        rename($file, CAP.$_SERVER['REMOTE_ADDR'].'-'.md5_file($file).'.cap');
    } else {
        unlink($file);
        return false;
    }

    return true;
}

//MAC conversions and checks
function mac2long($mac) {
    return hexdec(str_replace(':', '', $mac));
}

function long2mac($lmac) {
    $pmac = str_pad(dechex($lmac), 12, '0', STR_PAD_LEFT);
    return "{$pmac[0]}{$pmac[1]}:{$pmac[2]}{$pmac[3]}:{$pmac[4]}{$pmac[5]}:{$pmac[6]}{$pmac[7]}:{$pmac[8]}{$pmac[9]}:{$pmac[10]}{$pmac[11]}";
}

function valid_mac($mac) {
    return preg_match('/([a-f0-9]{2}:?){6}/', strtolower($mac));
}

//Write nets table
function write_nets($stmt, $data) {
    $has_input = false;
    echo '
<form class="form" method="POST" action="?nets" enctype="multipart/form-data">
<table style="border: 1;">
<tr><th>BSSID</th><th>SSID</th><th>WPA key</th><th>Timestamp</th></tr>';
    while ($stmt->fetch()) {
        $bssid = long2mac($data['bssid']);
        $ssid = htmlspecialchars($data['ssid']);
        if ($data['pass'] == '') {
            $pass = '<input class="input" type="text" name="'.$bssid.'" size="20"/>';
            $has_input = true;
        } else
            $pass = htmlspecialchars($data['pass']);
        $ts = $data['ts'];
        echo "<tr><td style=\"font:Courier;\">$bssid</td><td>$ssid</td><td>$pass</td><td>$ts</td></tr>\n";
    }
    echo '</table>';
    if ($has_input)
        echo '<input class="submitbutton" type="submit" value="Send WPA keys" />';
    echo '</form>';
}
?>
