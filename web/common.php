<?
//Execute aircrack-ng and check for solved net
function check_pass($bssid, $pass) {
    if (strlen($pass) < 8)
        return false;

    $wl = tempnam(SHM, 'wl');
    $kf = tempnam(SHM, 'key');
    $cf = tempnam(SHM, 'cap');

    //put test pass as wordlist
    file_put_contents($wl, $pass."\n");

    //deflate and put capture in shm
    //use gz compressed single captures - gzinflate fn -10 bytes
    file_put_contents($cf, gzinflate(substr(file_get_contents(CAPS.substr($bssid, -2).'/'.str_replace(':', '-', $bssid).'.gz'), 10)));

    exec(AIRCRACK." -b $bssid -w $wl -l $kf $cf");

    $p = @file_get_contents($kf);

    @unlink($wl);
    @unlink($kf);
    @unlink($cf);

    return ($p == $pass);
}

//Process submission
function submission($mysql, $file) {
    $bnfile = basename($file);
    $cleancap = SHM.$bnfile.'clean';

    //clean uploaded capture
    $res = '';
    $rc  = 0;
    exec(WPACLEAN." $cleancap $file", $res, $rc);
    if (($rc != 0) || (strpos(implode('',$res), 'Net ') === FALSE)) {
        @unlink($cleancap);
        @unlink($file);
        return false;
    }

    //put all uploaded nets bssid in $incap
    $incap = array();
    $nname = array();
    foreach ($res as $net)
        if (strlen($net) > 22) {
            $ibssid = mac2long(substr($net, 4, 17));
            $nname[$ibssid] = substr($net, 22);
            $incap[] = $ibssid;
        }

    //get all our bssids in $ourcap
    $ourcap = array();
    $res = $mysql->query('SELECT bssid FROM nets');
    while ($bssid = $res->fetch_row())
        $ourcap[] = $bssid[0];
    $res->free();

    //diff and cleanup
    $newnets = array_diff($incap, $ourcap);
    unset($incap);
    unset($ourcap);
    if (count($newnets) == 0)
        return false;

    //get u_id if we have key set
    $u_id = Null;
    if (isset($_COOKIE['key']))
        if (strlen($_COOKIE['key']) == 32) {
            $sql = 'SELECT u_id FROM users WHERE ukey=?';
            $stmt = $mysql->stmt_init();
            $stmt->prepare($sql);
            $stmt->bind_param('s', $_COOKIE['key']);
            $stmt->execute();
            $stmt->bind_result($u_id);
            $stmt->fetch();
            $stmt->close();
        }

    // Prepare nets for import
    $sql = 'INSERT IGNORE INTO nets(bssid, ssid, ip, u_id) VALUES(?, ?, ?, ?)';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);

    foreach ($newnets as $net) {
        $dotmac = long2mac($net);
        $maclast = substr($dotmac, -2);
        @mkdir(CAPS.$maclast);
        $cut = '';
        $rc  = 0;
        //strip only current handshake
        exec(TSHARK." -r $cleancap -R \"wlan.sa == $dotmac || wlan.da == $dotmac\" -w ".SHM.$bnfile, $cut, $rc);
        if ($rc == 0) {
            $cut = '';
            $rc  = 0;
            // run through pyrit analyze
            exec(PYRIT.' -r '.SHM.$bnfile.' analyze', $cut, $rc);
            if ($rc == 0) {
                $cut = file_get_contents(SHM.$bnfile);
                $gzdata = gzencode($cut, 9);
                file_put_contents(CAPS.$maclast.'/'.str_replace(':', '-', $dotmac).'.gz', $gzdata);
                //put in db
                $ip = ip2long($_SERVER['REMOTE_ADDR']);
                $stmt->bind_param('isii', $net, $nname[$net], $ip, $u_id);
                $stmt->execute();
            }
        }
    }
    $stmt->close();
    unset($nname);

    rename($file, CAP.$_SERVER['REMOTE_ADDR'].'-'.md5_file($file).'.cap');

    //update net count stats
    $sql = "UPDATE stats SET pvalue = (SELECT count(bssid) FROM nets) WHERE pname='nets'";
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $stmt->execute();
    $stmt->close();

    @unlink(SHM.$bnfile);
    @unlink($cleancap);
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
            if ($mcount++ > 20)
                break;
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

//Generate random key
function gen_key() {
    $fp = fopen('/dev/random','rb');
    $rand = fread($fp, 32);
    fclose($fp);
    return md5($rand);
}

/*
Validate an email address.
Provide email address (raw input)
Returns true if the email address has the email 
address format and the domain exists.
*/
function validEmail($email)
{
	$isValid = true;
	$atIndex = strrpos($email, "@");
	if (is_bool($atIndex) && !$atIndex) {
		$isValid = false; 
	} else {
		$domain = substr($email, $atIndex+1);
		$local = substr($email, 0, $atIndex);
		$localLen = strlen($local);
		$domainLen = strlen($domain);
		if ($localLen < 1 || $localLen > 64) {
			// local part length exceeded
			$isValid = false;
		} else if ($domainLen < 1 || $domainLen > 255) {
			// domain part length exceeded
			$isValid = false;
		} else if ($local[0] == '.' || $local[$localLen-1] == '.') {
			// local part starts or ends with '.'
			$isValid = false;
		} else if (preg_match('/\\.\\./', $local)) {
			// local part has two consecutive dots
			$isValid = false;
		} else if (!preg_match('/^[A-Za-z0-9\\-\\.]+$/', $domain)) {
			// character not valid in domain part
			$isValid = false;
		} else if (preg_match('/\\.\\./', $domain)) {
			// domain part has two consecutive dots
			$isValid = false;
		} else if (!preg_match('/^(\\\\.|[A-Za-z0-9!#%&`_=\\/$\'*+?^{}|~.-])+$/', str_replace("\\\\","",$local))) {
			// character not valid in local part unless 
			// local part is quoted
			if (!preg_match('/^"(\\\\"|[^"])+"$/', str_replace("\\\\","",$local))) {
				$isValid = false;
			}
		}
		if ($isValid && !(checkdnsrr($domain,"MX") || checkdnsrr($domain,"A"))) {
			// domain not found in DNS
			$isValid = false;
		}
	}
	return $isValid;
}

//convert num
function convert_num($num){
    $num = (float) $num;
    if ($num >= 1000000000000) {
        $tera = $num / 1000000000000;
        $size = sprintf('%.2fT', $tera);
    } elseif ($num >= 1000000000) {
        $giga = $num / 1000000000;
        $size = sprintf('%.2fG', $giga);
    } elseif ($num >= 1000000) {
        $mega = $num / 1000000;
        $size = sprintf('%.2fM', $mega);
    } elseif ($num >= 1000) {
        $kilo = $num / 1000;
        $size = sprintf('%.2fK', $kilo);
    } else
        $size = sprintf('%.2f', $num);
    return $size;
}

//Write nets table
function write_nets($stmt, $data) {
    $has_input = false;
    echo '
<style>
td {padding-left: 7px; padding-right: 7px}
</style>
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
        echo "<tr><td style=\"font-family:monospace; font-size: 12px;\">$bssid</td><td>$ssid</td><td>$pass</td><td align=\"right\">{$data['hits']}</td><td>{$data['ts']}</td></tr>\n";
    }
    echo '</table>';
    if ($has_input)
        echo '<input class="submitbutton" type="submit" value="Send WPA keys" />';
    echo '</form>';
}
?>
