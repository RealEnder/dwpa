<?php
//php 5.5 has this one
if (! function_exists('hash_pbkdf2')) {
    // based on https://defuse.ca/php-pbkdf2.htm
    function hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
    {
        $hash_length = array('sha1' => 20,
                             'md5'  => 16,);

        $block_count = ceil($key_length / $hash_length[$algorithm]);

        $output = '';
        for($i = 1; $i <= $block_count; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack("N", $i);
            // first iteration
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }

        if($raw_output)
            return substr($output, 0, $key_length);
        else
            return bin2hex(substr($output, 0, $key_length));
    }
}

// helper function for PHP version < 5.4.0
if (function_exists('hex2bin') == False) {
    /* Alternative working, but slow function
    function hex2bin($h) {
        if (strlen($h) % 2 != 0)
            $h = '0'.$h;
        if (!ctype_xdigit($h))
            return '';
        $r = '';
        for ($i=0; $i<strlen($h); $i+=2)
            $r .= chr(hexdec($h{$i}.$h{($i+1)}));
        return $r;
    }
    */
    function hex2bin($h) {
        if (strlen($h) & 1)
            $h = '0'.$h;

        return pack('H*', $h);
    }
}

/*
    check_key_hccapx(hccapx contents, array of keys)
    return:  False: bad format;
             Null: not found
             array('key_found',
                    0, //nonce correction value if used
                    'BE') //big endian(BE) or little endian(LE), if detected
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

function check_key_hccapx($hccapx, $keys, $nc=32767) {
    if (strlen($hccapx) != 393)
        return False;

    $ahccap = array();
    if (version_compare(PHP_VERSION, '5.5.0') >= 0) {
        $ahccap['essid'] = unpack('Z32', substr($hccapx, 0x00a, 32));
    } else {
        $ahccap['essid'] = unpack('a32', substr($hccapx, 0x00a, 32));
    }
    $ahccap['essid_len'] =         ord(substr($hccapx, 0x009, 1));
    $ahccap['mac_ap']    =             substr($hccapx, 0x03b, 6);
    $ahccap['mac_sta']   =             substr($hccapx, 0x061, 6);
    $ahccap['nonce_ap']  =             substr($hccapx, 0x041, 32);
    $ahccap['nonce_sta'] =             substr($hccapx, 0x067, 32);
    $ahccap['eapol']     =             substr($hccapx, 0x089, 256);
    $ahccap['eapol_len'] = unpack('S', substr($hccapx, 0x087, 2));
    $ahccap['keyver']    =         ord(substr($hccapx, 0x02a, 1));
    $ahccap['keymic']    =             substr($hccapx, 0x02b, 16);

    // fixup unpack
    $ahccap['essid']      = substr($ahccap['essid'][1], 0, $ahccap['essid_len']);
    $ahccap['eapol_len'] = $ahccap['eapol_len'][1];

    // cut eapol to right size
    $ahccap['eapol'] = substr($ahccap['eapol'], 0, $ahccap['eapol_len']);

    // fix order
    if (strncmp($ahccap['mac_ap'], $ahccap['mac_sta'], 6) < 0)
        $m = $ahccap['mac_ap'].$ahccap['mac_sta'];
    else
        $m = $ahccap['mac_sta'].$ahccap['mac_ap'];

    $swap = False;

    if (strncmp($ahccap['nonce_sta'], $ahccap['nonce_ap'], 6) < 0)
        $n = $ahccap['nonce_sta'].$ahccap['nonce_ap'];
    else {
        $n = $ahccap['nonce_ap'].$ahccap['nonce_sta'];
        $swap = True;
    }

    $last1 = substr($ahccap['nonce_ap'], 24, 4);
    $last2 = substr($ahccap['nonce_ap'], 28, 4);
    
    $last1le = unpack('V', $last1);
    $last2le = unpack('V', $last2);
    $last1be = unpack('N', $last1);
    $last2be = unpack('N', $last2);
    
    $corr['V'] = ($last1le[1] << 32) | $last2le[1];
    $corr['N'] = ($last1be[1] << 32) | $last2be[1];
    $halfnc = ($nc >> 1) + 1;
    $ncarr = array(array('N', 0));

    foreach ($keys as $key) {
        $kl = strlen($key);
        if (($kl < 8) || ($kl > 64))
            continue;

        $pmk = hash_pbkdf2('sha1', $key, $ahccap['essid'], 4096, 32, True);

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

                if ($ahccap['keyver'] == 1)
                    $testmic = hash_hmac('md5',  $ahccap['eapol'], substr($ptk, 0, 16), True);
                else
                    $testmic = hash_hmac('sha1', $ahccap['eapol'], substr($ptk, 0, 16), True);

                if (strncmp($testmic, $ahccap['keymic'], 16) == 0) {
                    if ($ncarr[0][1] == 0) {
                        return array($key, 0, Null);
                    } else {
                        if ($j[0] == 'N') {
                            return array($key, $j[1], 'BE');
                        } else {
                            return array($key, $j[1], 'LE');
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

function check_key($hccap, $keys, $nc=65535) {
    if (strlen($hccap) != 392)
        return False;

    $ahccap = array();
    if (version_compare(PHP_VERSION, '5.5.0') >= 0) {
        $ahccap['essid']      = unpack('Z36', substr($hccap, 0x000, 36));
    } else {
        $ahccap['essid']      = unpack('a36', substr($hccap, 0x000, 36));
    }
    $ahccap['mac1']       =               substr($hccap, 0x024, 6);
    $ahccap['mac2']       =               substr($hccap, 0x02a, 6);
    $ahccap['nonce1']     =               substr($hccap, 0x030, 32);
    $ahccap['nonce2']     =               substr($hccap, 0x050, 32);
    $ahccap['eapol']      =               substr($hccap, 0x070, 256);
    $ahccap['eapol_size'] = unpack('i',   substr($hccap, 0x170, 4));
    $ahccap['keyver']     = unpack('i',   substr($hccap, 0x174, 4));
    $ahccap['keymic']     =               substr($hccap, 0x178, 16);

    // fixup unpack
    $ahccap['essid']      = $ahccap['essid'][1];
    $ahccap['eapol_size'] = $ahccap['eapol_size'][1];
    $ahccap['keyver']     = $ahccap['keyver'][1];

    // cut eapol to right size
    $ahccap['eapol'] = substr($ahccap['eapol'], 0, $ahccap['eapol_size']);

    // fix order
    if (strncmp($ahccap['mac1'], $ahccap['mac2'], 6) < 0)
        $m = $ahccap['mac1'].$ahccap['mac2'];
    else
        $m = $ahccap['mac2'].$ahccap['mac1'];

    $swap = False;
    if (strncmp($ahccap['nonce1'], $ahccap['nonce2'], 6) < 0)
        $n = $ahccap['nonce1'].$ahccap['nonce2'];
    else {
        $n = $ahccap['nonce2'].$ahccap['nonce1'];
        $swap = True;
    }

    $last1 = substr($ahccap['nonce2'], 24, 4);
    $last2 = substr($ahccap['nonce2'], 28, 4);
    
    $last1le = unpack('V', $last1);
    $last2le = unpack('V', $last2);
    $last1be = unpack('N', $last1);
    $last2be = unpack('N', $last2);
    
    $corr['V'] = ($last1le[1] << 32) | $last2le[1];
    $corr['N'] = ($last1be[1] << 32) | $last2be[1];
    $halfnc = ($nc >> 1) + 1;
    $ncarr = array(array('N', 0));

    foreach ($keys as $key) {
        $kl = strlen($key);
        if (($kl < 8) || ($kl > 64))
            continue;

        $pmk = hash_pbkdf2('sha1', $key, $ahccap['essid'], 4096, 32, True);

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

                if ($ahccap['keyver'] == 1)
                    $testmic = hash_hmac('md5',  $ahccap['eapol'], substr($ptk, 0, 16), True);
                else
                    $testmic = hash_hmac('sha1', $ahccap['eapol'], substr($ptk, 0, 16), True);

                if (strncmp($testmic, $ahccap['keymic'], 16) == 0) {
                    return $key;
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

    return NULL;
}

//Extract partial md5 hash over hccapx struct
function hccapx_hash(& $hccapx) {
    //TODO: implement partial md5_64()
    return md5(substr($hccapx, 0x09), True);
}

//Process submission
function submission($mysql, $file) {
    //Internal functions
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
    if ($s_id != False) {
        $refi = array('');
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

            if (count($refi) > 1000) {
                insert_nets($mysql, $refi);
                $refi = array('');
            }
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

    //Update handshake stats
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets) WHERE pname='nets'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets) WHERE pname='nets_unc'");

    return True;
}

//Put work
function put_work($mysql, $candidates) {
    if (empty($candidates)) {
        return False;
    }

    function by_bssid(& $mysql, & $stmt, $bssid) {
        if ($stmt == Null) {
            $stmt = $mysql->stmt_init();
            $stmt->prepare('SELECT net_id, hccapx FROM nets WHERE bssid = ? AND n_state=0');
        }

        $ibssid = mac2long($bssid);
        $stmt->bind_param('i', $ibssid);
        $stmt->execute();
        $result = $stmt->get_result();
        $res = $result->fetch_all(MYSQLI_ASSOC);
        $result->free();

        return $res;
    }

    function by_hash(& $mysql, & $stmt, $hash) {
        if ($stmt == Null) {
            $stmt = $mysql->stmt_init();
            $stmt->prepare('SELECT net_id, hccapx FROM nets WHERE hash = UNHEX(?) AND n_state=0');
        }
        $stmt->bind_param('s', $hash);
        $stmt->execute();
        $result = $stmt->get_result();
        $res = $result->fetch_all(MYSQLI_ASSOC);
        $result->free();

        return $res;
    }

    function submit(& $mysql, & $stmt, $pass, $nc, $endian, $sip, $net_id) {
        if ($stmt == Null) {
            $stmt = $mysql->stmt_init();
            $stmt->prepare('UPDATE nets SET pass=?, nc=?, endian=?, sip=?, sts=NOW(), n_state=1 WHERE net_id=?');
        }

        $stmt->bind_param('sisii', $pass, $nc, $endian, $sip, $net_id);
        $stmt->execute();

        return;
    }

    function delete_from_n2d(& $mysql, & $stmt, $net_id) {
        if ($stmt == Null) {
            $stmt = $mysql->stmt_init();
            $stmt->prepare('DELETE FROM n2d WHERE net_id=?');
        }

        $stmt->bind_param('i', $net_id);
        $stmt->execute();

        return;
    }

    $bybssid_stmt = Null;
    $byhash_stmt = Null;
    $submit_stmt = Null;
    $n2d_stmt = Null;

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
                submit($mysql, $submit_stmt, $key, $res[1], $res[2], $iip, $net['net_id']);
                delete_from_n2d($mysql, $n2d_stmt, $net['net_id']);
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
    $n2d_stmt->close();

    //update cracked net stats
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE n_state=1) WHERE pname='cracked'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1) WHERE pname='cracked_unc'");

    //pull cracked wordlist
    $stmt = $mysql->stmt_init();
    $stmt->prepare('SELECT pass FROM (SELECT DISTINCT bssid, pass FROM nets WHERE n_state=1 GROUP BY bssid, pass) t GROUP BY pass ORDER BY count(pass) DESC');
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
