<?
define('AIRCRACK', 'aircrack-ng');
define('WPACLEAN', '/var/www/wpa-sec/cap/wpaclean');
define('WPA_CAP', '/var/www/wpa-sec/cap/wpa.cap');
define('CAP', '/var/www/wpa-sec/cap/');
define('CRACKED', '/var/www/wpa-sec/dict/cracked.txt.gz');

//Execute aircrack-ng and check for solved net
function check_pass($bssid, $pass) {
    $wl = '/tmp/wl';
    $kf = '/tmp/key';

    if (strlen($pass) < 8)
        return false;

    //start critical section
    $sem = sem_get(666);
    sem_acquire($sem);

    @unlink($kf);
    file_put_contents($wl, $pass."\n");

    $x = AIRCRACK." -b $bssid -w $wl -l $kf ".WPA_CAP;
    exec($x);

    $p = @file_get_contents($kf);

    //end critical section
    sem_release($sem);
    sem_remove($sem);

    return ($p == $pass);
}

//Process submission
function submission($mysql, $file) {
    $filtercap = $file.'filter';
    $res = '';
    $rc = 0;

    //start critical section
    $sem = sem_get(777);
    sem_acquire($sem);

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
                $nname = substr($net, 22);
                $ip = ip2long($_SERVER['REMOTE_ADDR']);
                $stmt->bind_param('isi', $mac, $nname, $ip );
                $stmt->execute();
            }
        }
        $stmt->close();
        rename($filtercap, WPA_CAP);
        rename($file, CAP.$_SERVER['REMOTE_ADDR'].'-'.md5_file($file).'.cap');
        //create gz and md5
        $cap = file_get_contents(WPA_CAP);
        $gzdata = gzencode($cap, 9);
        file_put_contents(WPA_CAP.'.gz', $gzdata);
        file_put_contents(WPA_CAP.'.gz.md5', md5_file(WPA_CAP.'.gz'));

        //end critical section
        sem_release($sem);
        sem_remove($sem);

        //update net count stats
        $sql = "UPDATE stats SET pvalue = (SELECT count(bssid) FROM nets) WHERE pname='nets'";
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        $stmt->execute();
        $stmt->close();
    } else {
        unlink($file);
        return false;
    }

    return true;
}

// Put work
function put_work($mysql) {
    if (empty($_POST))
        return false;

    $sql = 'SELECT * FROM nets WHERE bssid = ? AND n_state=0';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $data = array();
    stmt_bind_assoc($stmt, $data);

    //Update key stmt
    $usql = 'UPDATE nets SET pass=?, sip=?, n_state=1, sts=NOW() WHERE bssid=?';
    $ustmt = $mysql->stmt_init();
    $ustmt->prepare($usql);

    $mcount = 0;
    foreach ($_POST as $bssid => $key) {
        if ($mcount++ > 20)
            break;
        if (valid_mac($bssid) && strlen($key) >= 8) {
            $ibssid = mac2long($bssid);
            $stmt->bind_param('i', $ibssid);
            $stmt->execute();

            if ($stmt->fetch())
                if (check_pass($bssid, $key)) {
                    //put result in nets
                    $stmt->free_result();
                    $iip = ip2long($_SERVER['REMOTE_ADDR']);
                    $ustmt->bind_param('sii', $key, $iip, $ibssid);
                    $ustmt->execute();
                    //delete from n2d
                    $mysql->query("DELETE FROM n2d WHERE bssid=$ibssid");
                }
        }
    }
    $stmt->close();
    $ustmt->close();

    //Update cracked net stats
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(bssid) FROM nets WHERE n_state=1) WHERE pname='cracked'");

    //Create new cracked.txt.gz and update wcount
    $sql = 'SELECT pass FROM (SELECT pass, count(pass) AS c FROM nets WHERE n_state=1 GROUP BY pass) i ORDER BY i.c DESC';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $data = array();
    stmt_bind_assoc($stmt, $data);
    $stmt->execute();
    $wl = '';
    $i = 0;
    while ($stmt->fetch()) {
        $wl = "$wl{$data['pass']}\n";
        $i += 1;
    }
    $stmt->close();

    $gzdata = gzencode($wl, 9);
    
    $sem = sem_get(888);
    sem_acquire($sem);
    file_put_contents(CRACKED, $gzdata);
    file_put_contents(CRACKED.'.md5', md5($gzdata));
    sem_release($sem);
    sem_remove($sem);

    //update wcount for cracked dict
    $cr = '%'.basename(CRACKED);
    $sql = 'UPDATE dicts SET wcount = ? WHERE dpath LIKE ?';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $stmt->bind_param('is', $i, $cr);
    $stmt->execute();
    $stmt->close();

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
<tr><th>BSSID</th><th>SSID</th><th>WPA key</th><th>Get works</th><th>Timestamp</th></tr>';
    while ($stmt->fetch()) {
        $bssid = long2mac($data['bssid']);
        $ssid = htmlspecialchars($data['ssid']);
        if ($data['pass'] == '') {
            $pass = '<input class="input" type="text" name="'.$bssid.'" size="20"/>';
            $has_input = true;
        } else
            $pass = htmlspecialchars($data['pass']);
        echo "<tr><td style=\"font:Courier;\">$bssid</td><td>$ssid</td><td>$pass</td><td>{$data['hits']}</td><td>{$data['ts']}</td></tr>\n";
    }
    echo '</table>';
    if ($has_input)
        echo '<input class="submitbutton" type="submit" value="Send WPA keys" />';
    echo '</form>';
}
?>
