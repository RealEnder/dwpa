<?php
// Implements hashcat $HEX[]
function hc_unhex($key) {
    $k = substr($key, 5, -1);
    if (( (bool) (~ strlen($k) & 1)) &&
        (0 === substr_compare($key, '$HEX[', 0, 5)) &&
        (0 === substr_compare($key, ']', -1)) &&
        (ctype_xdigit($k))) {

        return hex2bin($k);
    }

    return $key;
}

/*
    check_key_hccapx(hccapx contents,
                     array of keys,
                     nonce correction to be used - positive integer,
                     binary PMK to be used)
    return:  False: bad format;
             Null: not found
             array('key_found',
                    0, //nonce correction value if used
                    'BE', //big endian(BE) or little endian(LE), if detected
                    PMK)
    hccapx structure https://hashcat.net/wiki/doku.php?id=hccapx

    #define HCCAPX_SIGNATURE 0x58504348 // HCPX
    struct hccapx
    {
      u32 signature;
      u32 version;
      u8  message_pair;
      u8  essid_len;
      u8  essid[32];
      u8  keyver;
      u8  keymic[16];
      u8  mac_ap[6];
      u8  nonce_ap[32];
      u8  mac_sta[6];
      u8  nonce_sta[32];
      u16 eapol_len;
      u8  eapol[256];

    } __attribute__((packed));
*/

function check_key_hccapx($hccapx, $keys, $nc=32767, $pmk=False) {
    if (strlen($hccapx) != 393)
        return False;

    $ahccapx = unpack('x8/Cmessage_pair/Cessid_len/a32essid/Ckeyver/a16keymic/a6mac_ap/a32nonce_ap/a6mac_sta/a32nonce_sta/veapol_len/a256eapol', $hccapx);

    // cut essid and eapol
    if ($ahccapx['essid_len'] < 32) {
        $ahccapx['essid'] = substr($ahccapx['essid'], 0, $ahccapx['essid_len']);
    }
    if ($ahccapx['eapol_len'] < 256) {
        $ahccapx['eapol'] = substr($ahccapx['eapol'], 0, $ahccapx['eapol_len']);
    }

    // fix order
    if (strncmp($ahccapx['mac_ap'], $ahccapx['mac_sta'], 6) < 0)
        $m = $ahccapx['mac_ap'].$ahccapx['mac_sta'];
    else
        $m = $ahccapx['mac_sta'].$ahccapx['mac_ap'];

    $swap = False;
    if (strncmp($ahccapx['nonce_sta'], $ahccapx['nonce_ap'], 6) < 0)
        $n = $ahccapx['nonce_sta'].$ahccapx['nonce_ap'];
    else {
        $n = $ahccapx['nonce_ap'].$ahccapx['nonce_sta'];
        $swap = True;
    }

    // get nonce_ap last bytes for nonce correction
    // TODO: unpack 64bit after April2019, this is PHP 5.6+
    $last1le = unpack('x24/V', $ahccapx['nonce_ap']);
    $last2le = unpack('x28/V', $ahccapx['nonce_ap']);
    $last1be = unpack('x24/N', $ahccapx['nonce_ap']);
    $last2be = unpack('x28/N', $ahccapx['nonce_ap']);

    $corr['V'] = ($last1le[1] << 32) | $last2le[1];
    $corr['N'] = ($last1be[1] << 32) | $last2be[1];
    $halfnc = ($nc >> 1) + 1;

    foreach ($keys as $key) {
        $key = hc_unhex($key);
        $kl = strlen($key);
        if (($kl < 8) || ($kl > 64))
            continue;

        if (! $pmk) {
            $pmk = hash_pbkdf2('sha1', $key, $ahccapx['essid'], 4096, 32, True);
        }

        $ncarr = array(array('N', 0));
        do {
            foreach ($ncarr as $j) {
                $rawlast1 = pack($j[0], $corr[$j[0]] + $j[1] >> 32);
                $rawlast2 = pack($j[0], $corr[$j[0]] + $j[1]);

                if ($swap) {
                    $n = substr_replace($n, $rawlast1.$rawlast2, 24, 8);
                } else {
                    $n = substr_replace($n, $rawlast1.$rawlast2, 56, 8);
                }

                $ptk = hash_hmac('sha1', "Pairwise key expansion\0".$m.$n."\0", $pmk, True);

                if ($ahccapx['keyver'] == 1)
                    $testmic = hash_hmac('md5',  $ahccapx['eapol'], substr($ptk, 0, 16), True);
                else
                    $testmic = hash_hmac('sha1', $ahccapx['eapol'], substr($ptk, 0, 16), True);

                if (strncmp($testmic, $ahccapx['keymic'], 16) == 0) {
                    if ($ncarr[0][1] == 0) {
                        return array($key, 0, Null, $pmk);
                    } else {
                        if ($j[0] == 'N') {
                            return array($key, $j[1], 'BE', $pmk);
                        } else {
                            return array($key, $j[1], 'LE', $pmk);
                        }
                    }
                    
                }
            }
            if ($ncarr[0][1] == 0) {
                $ncarr = array(array('V', 1), array('V', -1), array('N', 1), array('N', -1));
            } else {
                $ncarr[0][1] += 1;
                $ncarr[1][1] -= 1;
                $ncarr[2][1] += 1;
                $ncarr[3][1] -= 1;
            }
        } while ($ncarr[0][1]<=$halfnc);
    }

    return Null;
}

//Extract partial md5 hash over hccapx struct
function hccapx_hash(& $hccapx) {
    //TODO: implement partial md5_64()
    return md5(substr($hccapx, 0x09), True);
}

// Get handshakes by ssid, bssid, mac_sta
function get_handshakes(& $mysql, & $stmt, $ssid, $bssid, $mac_sta, $n_state) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT net_id, hccapx, ssid, pass, nc, bssid, mac_sta, pmk, sip FROM nets WHERE (ssid=? OR bssid=? OR mac_sta=?) AND n_state=?');
    }

    $stmt->bind_param('siii', $ssid, $bssid, $mac_sta, $n_state);
    $stmt->execute();
    $result = $stmt->get_result();
    $res = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();

    return $res;
}

// Update cracked handshake by hash
function submit_by_hash(& $mysql, & $stmt, $pass, $pmk, $nc, $endian, $sip, $hash) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('UPDATE nets SET pass=?, pmk=?, nc=?, endian=?, sip=?, sts=NOW(), n_state=1 WHERE hash=?');
    }

    $stmt->bind_param('ssisis', $pass, $pmk, $nc, $endian, $sip, $hash);
    $stmt->execute();

    return;
}

// Delete from n2d by hash
function delete_from_n2d_by_hash(& $mysql, & $stmt, $hash) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('DELETE FROM n2d WHERE net_id=(SELECT net_id FROM nets WHERE hash=?)');
    }

    $stmt->bind_param('s', $hash);
    $stmt->execute();

    return;
}

// Look for duplicate handshakes and mark submission array
function duplicate_nets(& $mysql, & $ref, & $nets) {
    if (count($ref) < 2) {
        return;
    }

    //get all net_ids of networks already in the DB
    $sql = 'SELECT hash FROM nets WHERE hash IN ('.implode(',', array_fill(0, count($ref)-1, '?')).')';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);

    $ref[0] = str_repeat('s', count($ref)-1);
    call_user_func_array(array($stmt, 'bind_param'), $ref);
    $stmt->execute();
    stmt_bind_assoc($stmt, $data);
    while ($stmt->fetch()) {
        //place skip mark - we have it in the db
        $nets[$data['hash']][100] = '';
    }
    $stmt->close();
}

// Handshake import
function insert_nets(& $mysql, & $ref) {
    if (count($ref) < 2) {
        return;
    }

    $bindvars = 'iiisssii';
    $sql = 'INSERT IGNORE INTO nets(s_id, bssid, mac_sta, ssid, hash, hccapx, message_pair, keyver) VALUES'.implode(',', array_fill(0, (count($ref)-1)/strlen($bindvars), '('.implode(',',array_fill(0, strlen($bindvars), '?')).')'));
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);

    $ref[0] = str_repeat($bindvars, (count($ref)-1)/strlen($bindvars));
    call_user_func_array(array($stmt, 'bind_param'), $ref);
    $stmt->execute();
    $stmt->close();
}

// Associate handshake to user
function insert_n2u(& $mysql, & $ref, $u_id) {
    if (count($ref) < 2) {
        return;
    }

    $sql = "INSERT IGNORE INTO n2u(net_id, u_id) SELECT net_id, $u_id FROM nets WHERE hash IN (".implode(',', array_fill(0, count($ref)-1, '?')).')';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);

    $ref[0] = str_repeat('s', count($ref)-1);
    call_user_func_array(array($stmt, 'bind_param'), $ref);
    $stmt->execute();
    $stmt->close();
}

//Process submission
function submission($mysql, $file) {
    //Extract handshakes from uploaded capture
    $hccapxfile = tempnam(SHM, 'hccapx');
    $res = '';
    $rc  = 0;
    exec(HCXPCAPTOOL." --nonce-error-corrections=128 --time-error-corrections=10000 -o $hccapxfile $file 2>&1", $res, $rc);

    //validate resulting hccapx file
    if (!file_exists($hccapxfile) || $rc != 0) {
        @unlink($file);
        return "Capture processing error. Exit code $rc. Please inform developers.";
    }
    $hccapxsize = filesize($hccapxfile);
    if ($hccapxsize == 0) {
        @unlink($hccapxfile);
        @unlink($file);
        return "No valid handshakes found in submitted file.";
    }
    if ($hccapxsize % 393 != 0) {
        @unlink($hccapxfile);
        @unlink($file);
        return "Capture file produced invalid hccapx struct of size $hccapxsize. Please inform developers.";
    }

    //move uploaded cap file
    $partial_path = date('Y/m/d/');
    if (!is_dir(CAP.$partial_path)) {
        mkdir(CAP.$partial_path, 0777, TRUE);
    }
    chmod($file, 0644);
    $capfile = CAP.$partial_path.$_SERVER['REMOTE_ADDR'].'-'.md5_file($file).'.cap';
    move_uploaded_file($file, $capfile);

    //insert into submissions table
    $sql = 'INSERT IGNORE INTO submissions(localfile, ip) VALUES(?, ?)';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $ip = ip2long($_SERVER['REMOTE_ADDR']);
    $stmt->bind_param('si', $capfile, $ip);
    $stmt->execute();
    $s_id = $stmt->insert_id;
    $stmt->close();

    $userkey = (isset($_COOKIE['key']) && valid_key($_COOKIE['key'])) ? $_COOKIE['key'] : '';
    if ($s_id == False && $userkey == '') {
        @unlink($hccapxfile);
        return 'This capture file was already submitted.';
    }

    //Read hccapx file and duplicate check
    $nets = array();
    $ref = array('');
    $fp = fopen($hccapxfile, 'rb');
    while (($hccapx = fread($fp, 393)) != FALSE) {
        $hash = hccapx_hash($hccapx);
        if (isset($nets[$hash])) {
            continue;
        }
        $nets[$hash] = array($hash, $hccapx);
        $ref[] = & $nets[$hash][0];
        if (count($ref) > 1000) {
            duplicate_nets($mysql, $ref, $nets);
            $ref = array('');
        }
    }
    fclose($fp);
    @unlink($hccapxfile);
    duplicate_nets($mysql, $ref, $nets);
    $ref = array('');

    //Insert identified handshakes
    $pmkarr = array();
    if ($s_id != False) {
        $refi = array('');
        $hs_stmt = Null;
        foreach ($nets as &$net) {
            //do we have a skip mark?
            if (array_key_exists(100, $net)) {
                continue;
            }
            //read from hccapx struct
            $essid_len = ord(substr($net[1], 0x09, 1));
            if (version_compare(PHP_VERSION, '5.5.0') >= 0) {
                $essid      = unpack('Z32', substr($net[1], 0x0a, 32));
            } else {
                $essid      = unpack('a32', substr($net[1], 0x0a, 32));
            }
            $essid = substr($essid[1], 0, $essid_len);
            $message_pair = ord(substr($net[1], 0x08, 1));
            $keyver = ord(substr($net[1], 0x2a, 1));

            $mac_ap = unpack('H*', substr($net[1], 0x3b, 6));
            $mac_ap = hexdec($mac_ap[1]);

            $mac_sta = unpack('H*', substr($net[1], 0x61, 6));
            $mac_sta = hexdec($mac_sta[1]);

            $net[2] = $mac_ap;
            $net[3] = $essid;
            $net[4] = $message_pair;
            $net[5] = $keyver;
            $net[6] = $mac_sta;
            $refi[] = & $s_id;
            $refi[] = & $net[2];
            $refi[] = & $net[6];
            $refi[] = & $net[3];
            $refi[] = & $net[0];
            $refi[] = & $net[1];
            $refi[] = & $net[4];
            $refi[] = & $net[5];

            // look for cracked handshakes with same features and try to crack current by PMK
            $hss = get_handshakes($mysql, $hs_stmt, $essid, $mac_ap, $mac_sta, 1);
            foreach ($hss as $hs) {
                if ($reshs = check_key_hccapx($net[1], array($hs['pass']), abs($hs['nc'])*2+128, $hs['pmk'])) {
                    $pmkarr[$net[0]] = array('key' => $reshs[0],
                                             'pmk' => $hs['pmk'],
                                             'nc' => $reshs[1],
                                             'endian' => $reshs[2],
                                             'sip' => $hs['sip']);
                    break;
                }
            }

            if (count($refi) > 1000) {
                insert_nets($mysql, $refi);
                $refi = array('');
            }
        }
        if ($hs_stmt) {
            $hs_stmt->close();
        }
        insert_nets($mysql, $refi);
        $refi = array('');

    }

    //Associate handshakes to user if we have key submitted
    if ($userkey != '') {
        $u_id = Null;
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT u_id FROM users WHERE userkey=UNHEX(?)');
        $stmt->bind_param('s', $userkey);
        $stmt->execute();
        $stmt->bind_result($u_id);
        $stmt->fetch();
        $stmt->close();

        //associate handshakes to user
        if ($u_id != Null) {
            $ref = array('');
            foreach ($nets as $net) {
                $ref[] = & $net[0];
                if (count($ref) > 1000) {
                    insert_n2u($mysql, $ref, $u_id);
                    $ref = array('');
                }
            }
            insert_n2u($mysql, $ref, $u_id);
            $ref = array();
        }
    }

    // Update handshakes cracked by PMK
    if (!empty($pmkarr)) {
        $submit_stmt = Null;
        $n2d_stmt = Null;
        foreach ($pmkarr as $hash => $val) {
            submit_by_hash($mysql, $submit_stmt, $val['key'], $val['pmk'], $val['nc'], $val['endian'], $val['sip'], $hash);
            delete_from_n2d_by_hash($mysql, $n2d_stmt, $hash);
        }
        $submit_stmt->close();
        $n2d_stmt->close();

        //update cracked net stats
        $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE n_state=1) WHERE pname='cracked'");
        $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1) WHERE pname='cracked_unc'");
    }

    //Update handshake stats
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets) WHERE pname='nets'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets) WHERE pname='nets_unc'");

    return True;
}

// Get uncracked handshake by bssid
function by_bssid(& $mysql, & $stmt, $bssid) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT net_id, hccapx, ssid, bssid, mac_sta FROM nets WHERE bssid = ? AND n_state=0');
    }

    $ibssid = mac2long($bssid);
    $stmt->bind_param('i', $ibssid);
    $stmt->execute();
    $result = $stmt->get_result();
    $res = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();

    return $res;
}

// Get uncracked handshake by hash
function by_hash(& $mysql, & $stmt, $hash) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT net_id, hccapx, ssid, bssid, mac_sta FROM nets WHERE hash = UNHEX(?) AND n_state=0');
    }
    $stmt->bind_param('s', $hash);
    $stmt->execute();
    $result = $stmt->get_result();
    $res = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();

    return $res;
}

// Update results by net_id
function submit_by_net_id(& $mysql, & $stmt, $pass, $pmk, $nc, $endian, $sip, $net_id) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('UPDATE nets SET pass=?, pmk=?, nc=?, endian=?, sip=?, sts=NOW(), n_state=1 WHERE net_id=?');
    }

    $stmt->bind_param('ssisii', $pass, $pmk, $nc, $endian, $sip, $net_id);
    $stmt->execute();

    return;
}

// Remove records from n2d for cracked handshake
function delete_from_n2d(& $mysql, & $stmt, $net_id) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('DELETE FROM n2d WHERE net_id=?');
    }

    $stmt->bind_param('i', $net_id);
    $stmt->execute();

    return;
}

//Put work
function put_work($mysql, $candidates) {
    if (empty($candidates)) {
        return False;
    }

    $bybssid_stmt = Null;
    $byhash_stmt = Null;
    $submit_stmt = Null;
    $n2d_stmt = Null;
    $hs_stmt = Null;

    $mcount = 0;
    foreach ($candidates as $bssid_or_hash => $key) {
        if (strlen($key) < 8) {
            continue;
        }

        //get hccapx structs by bssid or hash
        if (valid_mac($bssid_or_hash)) {
            $nets = by_bssid($mysql, $bybssid_stmt, $bssid_or_hash);
        } elseif (valid_key($bssid_or_hash)) {
            $nets = by_hash($mysql, $byhash_stmt, $bssid_or_hash);
        } else {
            continue;
        }

        //check PSK candidate against hccapx
        foreach ($nets as $net) {
            if ($res = check_key_hccapx($net['hccapx'], array($key))) {
                $iip = ip2long($_SERVER['REMOTE_ADDR']);
                submit_by_net_id($mysql, $submit_stmt, $res[0], $res[3], $res[1], $res[2], $iip, $net['net_id']);
                delete_from_n2d($mysql, $n2d_stmt, $net['net_id']);

                // check for other crackable handshakes by PMK
                $hss = get_handshakes($mysql, $hs_stmt, $net['ssid'], $net['bssid'], $net['mac_sta'], 0);
                foreach ($hss as $hs) {
                    if ($reshs = check_key_hccapx($hs['hccapx'], array($key), abs($res[1])*2+128, $res[3])) {
                        submit_by_net_id($mysql, $submit_stmt, $res[0], $res[3], $reshs[1], $reshs[2], $iip, $hs['net_id']);
                        delete_from_n2d($mysql, $n2d_stmt, $hs['net_id']);
                    }
                }
            }
        }

        if ($mcount++ > 200)
            break;
    }

    //cleanup stmts
    if ($bybssid_stmt) {
        $bybssid_stmt->close();
    }
    if ($byhash_stmt) {
        $byhash_stmt->close();
    }
    //if we haven't accepted valid PSK just exit
    if (!$submit_stmt) {
        return False;
    }
    $submit_stmt->close();
    if ($hs_stmt) {
        $hs_stmt->close();
    }
    $n2d_stmt->close();

    //update cracked net stats
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE n_state=1) WHERE pname='cracked'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1) WHERE pname='cracked_unc'");

    //pull cracked wordlist
    $stmt = $mysql->stmt_init();
    $stmt->prepare("SELECT pass FROM (SELECT pass, count(pass) AS c FROM nets WHERE n_state=1 AND (algo IS NULL OR algo = '') GROUP BY pass) i ORDER BY i.c DESC");
    $stmt->execute();
    $stmt->bind_result($key);

    //write compressed wordlist
    $wpakeys = tempnam(SHM, 'wpakeys');
    chmod($wpakeys, 0644);
    $fd = gzopen($wpakeys, 'wb9');
    while ($stmt->fetch()) {
        gzwrite($fd, "$key\n");
    }
    $keycount = $stmt->num_rows;
    $stmt->close();
    fflush($fd);
    gzclose($fd);

    $md5 = md5_file($wpakeys, True);
    rename($wpakeys, CRACKED);

    //update wcount for cracked dict
    $cr = '%'.basename(CRACKED);
    $sql = 'UPDATE dicts SET wcount = ?, dhash = ? WHERE dpath LIKE ?';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $stmt->bind_param('iss', $keycount, $md5, $cr);
    $stmt->execute();
    $stmt->close();

    return True;
}

//MAC conversions and checks
function mac2long($mac) {
    return hexdec(str_replace(':', '', $mac));
}

function long2mac($lmac) {
    $pmac = str_pad(dechex($lmac), 12, '0', STR_PAD_LEFT);
    return "{$pmac[0]}{$pmac[1]}:{$pmac[2]}{$pmac[3]}:{$pmac[4]}{$pmac[5]}:{$pmac[6]}{$pmac[7]}:{$pmac[8]}{$pmac[9]}:{$pmac[10]}{$pmac[11]}";
}

function valid_mac($mac, $part=6) {
    return preg_match('/^([a-f0-9]{2}\:?){'.$part.'}$/', strtolower($mac));
}

//Generate random key
function gen_key() {
    $fp = fopen('/dev/urandom','rb');
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
function validEmail($email) {
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
function convert_num($num) {
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

//convert seconds to text
function convert_sec($secs) {
    $units = array (
        'year'   => 29030400, // seconds in a year   (12 months)
        'month'  => 2419200,  // seconds in a month  (4 weeks)
        'day'    => 86400,    // seconds in a day    (24 hours)
        'hour'   => 3600      // seconds in an hour  (60 minutes)
    );
    $output='';

    foreach($units as $unit => $mult)
        if($secs >= $mult) {
            $and = (($mult != 1) ? ('') : ('and '));
            $output .= ', '.$and.intval($secs / $mult).' '.$unit.((intval($secs / $mult) == 1) ? ('') : ('s'));
            $secs -= intval($secs / $mult) * $mult;
        }

    //remove leading ,
    return substr($output, 2);
}

//Write nets table
function write_nets($datas) {
    $has_input = False;
    echo '
<style type="text/css">
td {padding-left: 7px; padding-right: 7px}
</style>
<form class="form" method="post" action="?nets" enctype="multipart/form-data">
<table style="border: 1;">
<tr><th>BSSID</th><th>SSID</th><th>WPA key</th><th>Get works</th><th>Timestamp</th></tr>';
    foreach ($datas as $data) {
        $bssid = long2mac($data['bssid']);
        $hash = $data['hash'];
        $ssid = htmlspecialchars($data['ssid']);
        if ($data['pass'] == '') {
            $pass = '<input class="input" type="text" name="'.$hash.'" size="20"/>';
            $has_input = True;
        } else {
            $pass = htmlspecialchars($data['pass']);
        }
        echo "<tr><td style=\"font-family:monospace; font-size: 12px; cursor: pointer; \"><a title=\"Wigle geo query. You must be logged in.\" href=\"https://wigle.net/search?netid=$bssid\">$bssid</a></td><td>$ssid</td><td>$pass</td><td align=\"right\">{$data['hits']}</td><td>{$data['ts']}</td></tr>\n";
    }
    echo '</table>';
    if ($has_input) {
        echo '<input class="submitbutton" type="submit" value="Send WPA keys" />';
    }
    echo '</form>';
}
?>
