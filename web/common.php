<?php
// Implements hashcat $HEX[]
function hc_unhex($key) {
    if (strlen($key) <= 6) {
        return $key;
    }

    $k = substr($key, 5, -1);
    if (( (bool) (~ strlen($k) & 1)) &&
        (0 === substr_compare($key, '$HEX[', 0, 5)) &&
        (0 === substr_compare($key, ']', -1)) &&
        (ctype_xdigit($k))) {

        return hex2bin($k);
    }

    if ( ($k == '') &&
        (0 === substr_compare($key, '$HEX[', 0, 5)) &&
        (0 === substr_compare($key, ']', -1))) {

        return '';
    }

    return $key;
}

// Is valid hex string
function valid_hex($str) {
    if (( (bool) (~ strlen($str) & 1)) &&
        (ctype_xdigit($str))) {

        return True;
    }

    return False;
}

// Used by omac1_aes_128()
function omac1_aes_128_leftShift($data, $bits) {
    $mask   = (0xff << (8 - $bits)) & 0xff;
    $state  = 0;
    $result = '';
    $length = strlen($data);
    for ($i = $length - 1; $i >= 0; $i--) {
        $tmp     = ord($data[$i]);
        $result .= chr(($tmp << $bits) | $state);
        $state   = ($tmp & $mask) >> (8 - $bits);
    }

    return strrev($result);
}

// Implements omac1_aes_128 (cmac)
// Based on https://github.com/ircmaxell/PHP-CryptLib
function omac1_aes_128($data, $key) {
    // generate keys
    $keys      = array();
    $blockSize = 16;
    // this is based on blocksize * 8
    //   64:  str_repeat(chr(0), 7) . chr(0x1B)
    //   128: str_repeat(chr(0), 15) . chr(0x87)
    $rVal      = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x87";
    // this must be block size in length
    $cBlock    = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    $lVal      = openssl_encrypt($cBlock, 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

    $keys[0] = omac1_aes_128_leftShift($lVal, 1);
    if (ord($lVal[0]) > 127) {
        $keys[0] = $keys[0] ^ $rVal;
    }
    $keys[1] = omac1_aes_128_leftShift($keys[0], 1);
    if (ord($keys[0][0]) > 127) {
        $keys[1] = $keys[1] ^ $rVal;
    }

    // split data into mBlocks
    $mBlocks = str_split($data, $blockSize);
    $last = end($mBlocks);
    if (strlen($last) != $blockSize) {
        // pad the last element
        $last .= "\x80" . str_repeat("\0", $blockSize - 1 - strlen($last));
        $last  = $last ^ $keys[1];
    } else {
        $last = $last ^ $keys[0];
    }
    $mBlocks[count($mBlocks) - 1] = $last;

    // work on all blocks
    foreach ($mBlocks as $block) {
        $cBlock = openssl_encrypt($cBlock ^ $block, 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    }

    // for other block sizes we must cut: substr($cBlock, 0, $blockSize)
    return $cBlock;
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

function check_key_hccapx($hccapx, $keys, $nc=512, $pmk=False) {
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
        if (strlen($key) > 20) {
            $key = hc_unhex($key);
        }

        if (! $pmk) {
            $kl = strlen($key);
            if (($kl < 8) || ($kl > 64)) {
                continue;
            }
            $pmk = openssl_pbkdf2($key, $ahccapx['essid'], 32, 4096, 'sha1');
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

                switch ($ahccapx['keyver']) {
                    case 1:
                        $ptk = hash_hmac('sha1', "Pairwise key expansion\0".$m.$n."\0", $pmk, True);
                        $testmic = hash_hmac('md5',  $ahccapx['eapol'], substr($ptk, 0, 16), True);
                        break;
                    case 2:
                        $ptk = hash_hmac('sha1', "Pairwise key expansion\0".$m.$n."\0", $pmk, True);
                        $testmic = hash_hmac('sha1', $ahccapx['eapol'], substr($ptk, 0, 16), True);
                        break;
                    case 3:
                        $ptk = hash_hmac('sha256', "\1\0Pairwise key expansion".$m.$n."\x80\1", $pmk, True);
                        $testmic = omac1_aes_128($ahccapx['eapol'], substr($ptk, 0, 16));
                        break;
                    default:
                        // unknown keyver
                        return Null;
                }

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
        $pmk = False;
    }

    return Null;
}

/*
    check_key_pmkid(pmkidline contents,
                     array of keys,
                     binary PMK to be used)
    return:  False: bad format;
             Null: not found
             array('key_found',
                    Null,
                    Null,
                    PMK)
    PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)
    $pmkidline = PMKID*MAC AP*MAC Station*ESSID
    All is hex encoded
*/

function check_key_pmkid($pmkidline, $keys, $pmk=False) {
    // split and check
    $apmkid = explode('*', $pmkidline, 4);
    if (count($apmkid) != 4)
        return False;

    // unhex
    for ($i=0; $i <= 3; $i++) {
        if (( (bool) (~ strlen($apmkid[$i]) & 1)) &&
            (ctype_xdigit($apmkid[$i]))) {

            $apmkid[$i] = hex2bin($apmkid[$i]);
        } else {
            return False;
        }
    }

    foreach ($keys as $key) {
        if (strlen($key) > 20) {
            $key = hc_unhex($key);
        }

        if (! $pmk) {
            $kl = strlen($key);
            if (($kl < 8) || ($kl > 64)) {
                continue;
            }
            $pmk = openssl_pbkdf2($key, $apmkid[3], 32, 4096, 'sha1');
        }

        // compute PMKID candidate
        $testpmkid = hash_hmac('sha1', 'PMK Name' . $apmkid[1] . $apmkid[2], $pmk, True);

        if (strncmp($testpmkid, $apmkid[0], 16) == 0) {
            return array($key, Null, Null, $pmk);
        }
        $pmk = False;
    }

    return Null;
}

// Extract md5 hash over partial hccapx struct
function hccapx_hash(& $hccapx) {
    return md5(substr($hccapx, 0x09), True);
}

// Create filesystem lock file or wait until we can create one
// Proceed if the lockfile is older than 1 minute
function create_lock($lockfile) {
    while (file_exists(SHM.$lockfile) && (time()-filemtime(SHM.$lockfile) <= 60)) {
        sleep(1);
    }
    touch(SHM.$lockfile);
}

// Release filesystem lock file if exists
function release_lock($lockfile) {
    if (file_exists(SHM.$lockfile)) {
        @unlink(SHM.$lockfile);
    }
}

// Get handshakes/PMKIDs by ssid, bssid, mac_sta
function get_handshakes(& $mysql, & $stmt, $ssid, $bssid, $mac_sta, $n_state) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT net_id, struct, ssid, pass, nc, bssid, mac_sta, pmk, sip, keyver, algo
FROM nets
WHERE (ssid=? OR bssid=? OR mac_sta=?)
AND n_state=?');
    }

    $stmt->bind_param('siii', $ssid, $bssid, $mac_sta, $n_state);
    $stmt->execute();
    $result = $stmt->get_result();
    $res = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();

    return $res;
}

// Update cracked handshake by hash
function submit_by_hash(& $mysql, & $stmt, $pass, $pmk, $nc, $endian, $sip, $algo, $hash) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('UPDATE nets SET pass=?, pmk=?, nc=?, endian=?, sip=?, algo=?, sts=NOW(), n_state=1 WHERE hash=?');
    }

    $stmt->bind_param('ssisiss', $pass, $pmk, $nc, $endian, $sip, $algo, $hash);
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
    $sql = 'INSERT IGNORE INTO nets(s_id, bssid, mac_sta, ssid, hash, struct, message_pair, keyver) VALUES'.implode(',', array_fill(0, (count($ref)-1)/strlen($bindvars), '('.implode(',',array_fill(0, strlen($bindvars), '?')).')'));
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

// Validate capture file
function valid_cap($file) {
    if (is_readable($file) && filesize($file) > 64) {
        // misuse gz functions to read also cleartext
        $fgz = gzopen($file, 'rb');
        $mn = gzread($fgz, 4);
        gzclose($fgz);

        if (   $mn == "\x0a\x0d\x0d\x0a" // pcapng magic number
            || $mn == "\xa1\xb2\xc3\xd4" // pcap magic number
            || $mn == "\xd4\xc3\xb2\xa1" // pcap magic number BE
            ) {
            return True;
        }
    }

    return False;
}

// Process submission
function submission($mysql, $file) {
    // check for valid capture submission
    if (!valid_cap($file)) {
        return "Not a valid capture file. We support pcap and pcapng.";
    }

    // extract handshakes and PMKIDs from uploaded capture
    $hccapxfile = tempnam(SHM, 'hccapx');
    $pmkidfile = tempnam(SHM, 'pmkid');
    $res = '';
    $rc  = 0;
    exec(HCXPCAPTOOL." --time-error-corrections=10000 --ignore-fake-frames --ignore-zeroed-pmks --ignore-replaycount --ignore-mac -o $hccapxfile -z $pmkidfile $file 2>&1", $res, $rc);

    // do we have error condition?
    if ($rc != 0) {
        @unlink($file);
        return "Capture processing error. Exit code $rc. Please inform developers.";
    }

    // add submission
    if (file_exists($hccapxfile) || file_exists($pmkidfile)) {
        // compute hash and create new capture name
        $partial_path = date('Y/m/d/');
        $md5 = md5_file($file, True);
        $capfile = CAP.$partial_path.$_SERVER['REMOTE_ADDR'].'-'.bin2hex($md5).'.cap';

        //insert into submissions table
        $sql = 'INSERT IGNORE INTO submissions(localfile, hash, ip) VALUES(?, ?, ?)';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        $ip = ip2long($_SERVER['REMOTE_ADDR']);
        $stmt->bind_param('ssi', $capfile, $md5, $ip);
        $stmt->execute();
        $s_id = $stmt->insert_id;
        $stmt->close();

        // move capture only if it's new
        if ($s_id) {
            if (!is_dir(CAP.$partial_path)) {
                mkdir(CAP.$partial_path, 0777, True);
            }

            chmod($file, 0644);
            move_uploaded_file($file, $capfile);
        }

        $userkey = (isset($_COOKIE['key']) && valid_key($_COOKIE['key'])) ? $_COOKIE['key'] : '';
        if ($s_id == False && $userkey == '') {
            @unlink($hccapxfile);
            @unlink($pmkidfile);
            return 'This capture file was already submitted.';
        }
    } else {
        @unlink($file);
        return "No valid handshakes/PMKIDs found in submitted file.";
    }

    $nets = array();
    $ref = array('');

    // read hccapx file
    if (file_exists($hccapxfile)
        && filesize($hccapxfile) != 0
        && filesize($hccapxfile) % 393 == 0) {
        $fp = fopen($hccapxfile, 'rb');
        while (($hccapx = fread($fp, 393)) != False) {
            $hash = hccapx_hash($hccapx);
            if (isset($nets[$hash])) {
                continue;
            }
            $nets[$hash] = array($hash, $hccapx, 0);
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
    }

    // read pmkid file
    if (file_exists($pmkidfile)
        && filesize($pmkidfile) > 0) {
        $fp = fopen($pmkidfile, 'r');
        while (($pmkidline = fgets($fp)) != False) {
            $pmkidline = rtrim($pmkidline);
            // validate PMKID line
            $apmkid = explode('*', $pmkidline, 4);
            if (count($apmkid) != 4) {
                continue;
            }
            for ($i=0; $i <= 3; $i++) {
                if ( !(((bool) (~ strlen($apmkid[$i]) & 1)) && (ctype_xdigit($apmkid[$i]))) ) {
                    continue;
                }
            }
            // get hash from PMKID*mac_ap*mac_sta
            $hash = md5(substr($pmkidline, 0, 58), True);
            if (isset($nets[$hash])) {
                continue;
            }
            $nets[$hash] = array($hash, $pmkidline, 1);
            $ref[] = & $nets[$hash][0];
            if (count($ref) > 1000) {
                duplicate_nets($mysql, $ref, $nets);
                $ref = array('');
            }
        }
        fclose($fp);
        @unlink($pmkidfile);
        duplicate_nets($mysql, $ref, $nets);
        $ref = array('');
    }

    // insert identified handshakes/PMKIDs
    $zpmk = str_repeat("\0", 32);
    $pmkarr = array();
    if ($s_id != False) {
        $refi = array('');
        $hs_stmt = Null;
        foreach ($nets as &$net) {
            // do we have a skip mark?
            if (array_key_exists(100, $net)) {
                continue;
            }

            // read from hccapx struct
            if ($net[2] == 0) {
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
            }

            // read from pmkid hash line
            if ($net[2] == 1) {
                $apmkid = explode('*', $net[1], 4);

                $mac_ap = hexdec($apmkid[1]);
                $mac_sta = hexdec($apmkid[2]);
                $essid = hex2bin($apmkid[3]);

                $message_pair = Null;
                $keyver = 100;
            }


            $net[2] = $mac_ap;
            $net[3] = $essid;
            $net[4] = $message_pair;
            $net[5] = $keyver;
            $net[6] = $mac_sta;

            // check for zeroed PMK
            if ($keyver == 100) {
                $reshs = check_key_pmkid($net[1], array(''), $zpmk);
            } else {
                $reshs = check_key_hccapx($net[1], array(''), 8, $zpmk);
            }
            if ($reshs) {
                // this is zeroed PMK
                $pmkarr[$net[0]] = array('key' => '',
                                         'pmk' => $zpmk,
                                         'nc' => $reshs[1],
                                         'endian' => $reshs[2],
                                         'sip' => 2130706433,
                                         'algo' => 'ZeroPMK');
            } else {
                // look for cracked handshakes/PMKIDs with same features and try to crack current by PMK
                $broken_essid = False;
                $hss = get_handshakes($mysql, $hs_stmt, $essid, $mac_ap, $mac_sta, 1);
                foreach ($hss as $hs) {
                    if ($keyver == 100) {
                        $reshs = check_key_pmkid($net[1], array($hs['pass']), $hs['pmk']);
                    } else {
                        $reshs = check_key_hccapx($net[1], array($hs['pass']), abs($hs['nc'])*2+1, $hs['pmk']);
                    }
                    if ($reshs) {
                        // we cracked that by PMK, now let's check if essid matches
                        // if this not pass, we have broken essid and we'll skip this net.
                        if ($essid === $hs['ssid']) {
                            $pmkarr[$net[0]] = array('key' => $reshs[0],
                                                     'pmk' => $hs['pmk'],
                                                     'nc' => $reshs[1],
                                                     'endian' => $reshs[2],
                                                     'sip' => $hs['sip'],
                                                     'algo' => $hs['algo']);
                        } else {
                            $broken_essid = True;
                        }
                        break;
                    }
                }

                if ($broken_essid) {
                    continue;
                }
            }

            // prepare values for insert
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
        if ($hs_stmt) {
            $hs_stmt->close();
        }
        insert_nets($mysql, $refi);
        $refi = array('');

    }

    // associate nets to user if we have key submitted
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

    // update nets cracked by PMK
    if (!empty($pmkarr)) {
        $submit_stmt = Null;
        $n2d_stmt = Null;
        foreach ($pmkarr as $hash => $val) {
            submit_by_hash($mysql, $submit_stmt, $val['key'], $val['pmk'], $val['nc'], $val['endian'], $val['sip'], $val['algo'], $hash);
            delete_from_n2d_by_hash($mysql, $n2d_stmt, $hash);
        }
        $submit_stmt->close();
        $n2d_stmt->close();

        // update cracked net stats
        $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE n_state=1) WHERE pname='cracked'");
        $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1) WHERE pname='cracked_unc'");
        $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE n_state=1 AND keyver=100) WHERE pname='cracked_pmkid'");
        $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1 AND keyver=100) WHERE pname='cracked_pmkid_unc'");
    }

    // update handshake stats
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets) WHERE pname='nets'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(1) FROM bssids) WHERE pname='nets_unc'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE keyver=100) WHERE pname='pmkid'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE keyver=100) WHERE pname='pmkid_unc'");

    return implode("\n", $res);
}

// Get uncracked nets by bssid
function by_bssid(& $mysql, & $stmt, $bssid) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT net_id, struct, ssid, bssid, mac_sta, keyver FROM nets WHERE bssid = ? AND n_state=0');
    }

    $ibssid = mac2long($bssid);
    $stmt->bind_param('i', $ibssid);
    $stmt->execute();
    $result = $stmt->get_result();
    $res = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();

    return $res;
}

// Get uncracked net by hash
function by_hash(& $mysql, & $stmt, $hash) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT net_id, struct, ssid, bssid, mac_sta, keyver FROM nets WHERE hash = UNHEX(?) AND n_state=0');
    }
    $stmt->bind_param('s', $hash);
    $stmt->execute();
    $result = $stmt->get_result();
    $res = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();

    return $res;
}

// Get uncracked nets by essid
function by_essid(& $mysql, & $stmt, $essid) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT net_id, struct, ssid, bssid, mac_sta, keyver FROM nets WHERE ssid = UNHEX(?) AND n_state=0');
    }
    $stmt->bind_param('s', $essid);
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

// Deletes from rkg, n2u, n2d, and nets by net_id
// This is used to remove handshakes/PMKIDs with broken essids
function delete_cascade_by_net_id(& $mysql, $net_id) {
    $mysql->begin_transaction(MYSQLI_TRANS_START_READ_WRITE);

    $stmt = $mysql->stmt_init();
    $stmt->prepare('DELETE FROM rkg WHERE net_id=?');
    $stmt->bind_param('i', $net_id);
    $stmt->execute();
    $stmt->close();
    $stmt = $mysql->stmt_init();
    $stmt->prepare('DELETE FROM n2u WHERE net_id=?');
    $stmt->bind_param('i', $net_id);
    $stmt->execute();
    $stmt->close();
    $stmt = $mysql->stmt_init();
    $stmt->prepare('DELETE FROM n2d WHERE net_id=?');
    $stmt->bind_param('i', $net_id);
    $stmt->execute();
    $stmt->close();

    // check how many bssids with deleted net_id bssid we have
    $n_count = Null;
    $stmt = $mysql->stmt_init();
    $stmt->prepare('SELECT count(*) FROM nets WHERE bssid = (SELECT bssid FROM nets WHERE net_id=?)');
    $stmt->bind_param('i', $net_id);
    $stmt->execute();
    $stmt->bind_result($n_count);
    $stmt->fetch();
    $stmt->close();
    // delete from bssids if we have only one such net
    if ($n_count == 1) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('DELETE FROM bssids WHERE bssid = (SELECT bssid FROM nets WHERE net_id=?)');
        $stmt->bind_param('i', $net_id);
        $stmt->execute();
        $stmt->close();
    }
    $stmt = $mysql->stmt_init();
    $stmt->prepare('DELETE FROM nets WHERE net_id=?');
    $stmt->bind_param('i', $net_id);
    $stmt->execute();
    $stmt->close();

    $mysql->commit();

    return;
}

// Put work
function put_work($mysql, $candidates) {
    if (empty($candidates)) {
        return False;
    }

    $bybssid_stmt = Null;
    $byhash_stmt = Null;
    $byessid_stmt = Null;
    $submit_stmt = Null;
    $n2d_stmt = Null;
    $hs_stmt = Null;

    $mcount = 0;
    foreach ($candidates as $bssid_or_hash => $key) {
        if (strlen($key) < 8) {
            continue;
        }

        // remove bssid padding if found
        if (strlen($bssid_or_hash) == 21 && valid_mac(substr($bssid_or_hash, -17))) {
            $bssid_or_hash = substr($bssid_or_hash, -17);
        }

        // get nets by bssid, hash or essid
        if (valid_mac($bssid_or_hash)) {
            $nets = by_bssid($mysql, $bybssid_stmt, $bssid_or_hash);
        } elseif (valid_key($bssid_or_hash)) {
            $nets = by_hash($mysql, $byhash_stmt, $bssid_or_hash);
        } elseif (strlen($bssid_or_hash) > 4 && valid_hex(substr($bssid_or_hash, 4))) {
            $bssid_or_hash = substr($bssid_or_hash, 4);
            $nets = by_essid($mysql, $byessid_stmt, $bssid_or_hash);
        } else {
            continue;
        }

        // check PSK candidate against struct
        foreach ($nets as $net) {
            if ($net['keyver'] == 100) {
                $res = check_key_pmkid($net['struct'], array($key));
            } else {
                $res = check_key_hccapx($net['struct'], array($key));
            }

            if ($res) {
                $iip = ip2long($_SERVER['REMOTE_ADDR']);
                submit_by_net_id($mysql, $submit_stmt, $res[0], $res[3], $res[1], $res[2], $iip, $net['net_id']);
                delete_from_n2d($mysql, $n2d_stmt, $net['net_id']);

                // check for other crackable nets by PMK
                $broken_essid = False;
                $hss = get_handshakes($mysql, $hs_stmt, $net['ssid'], $net['bssid'], $net['mac_sta'], 0);
                foreach ($hss as $hs) {
                    if ($hs['keyver'] == 100) {
                        $reshs = check_key_pmkid($hs['struct'], array($key), $res[3]);
                    } else {
                        $reshs = check_key_hccapx($hs['struct'], array($key), abs($res[1])*2+128, $res[3]);
                    }
                    if ($reshs) {
                        // we cracked that by PMK, now let's check if essid matches
                        // if this not pass, we have broken essid and we'll delete this net.
                        if ($net['ssid'] === $hs['ssid']) {
                            submit_by_net_id($mysql, $submit_stmt, $res[0], $res[3], $reshs[1], $reshs[2], $iip, $hs['net_id']);
                            delete_from_n2d($mysql, $n2d_stmt, $hs['net_id']);
                        } else {
                            delete_cascade_by_net_id($mysql, $hs['net_id']);
                        }
                    }

                }

            }
        }

        if ($mcount++ > 200)
            break;
    }

    // cleanup stmts
    if ($bybssid_stmt) {
        $bybssid_stmt->close();
    }
    if ($byhash_stmt) {
        $byhash_stmt->close();
    }
    // if we haven't accepted valid PSK just exit
    if (!$submit_stmt) {
        return False;
    }
    $submit_stmt->close();
    if ($hs_stmt) {
        $hs_stmt->close();
    }
    $n2d_stmt->close();

    // update cracked net stats
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE n_state=1) WHERE pname='cracked'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1) WHERE pname='cracked_unc'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE n_state=1 AND keyver=100) WHERE pname='cracked_pmkid'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1 AND keyver=100) WHERE pname='cracked_pmkid_unc'");

    // pull cracked wordlist
    $stmt = $mysql->stmt_init();
    $stmt->prepare("SELECT BINARY pass AS pass
FROM (SELECT bssid, BINARY pass AS pass
      FROM nets
      WHERE n_state=1 AND
      (algo IS NULL OR algo = '') AND
      LENGTH(pass) >= 8
      GROUP BY bssid, BINARY pass) t
GROUP BY BINARY pass
ORDER BY count(pass) DESC");
    $stmt->execute();
    $stmt->bind_result($key);

    // write compressed wordlist
    $wpakeys = tempnam(CAP, 'wpakeys');
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

    // update wcount for cracked dict
    $cr = '%'.basename(CRACKED);
    $sql = 'UPDATE dicts SET wcount = ?, dhash = ? WHERE dpath LIKE ?';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $stmt->bind_param('iss', $keycount, $md5, $cr);
    $stmt->execute();
    $stmt->close();

    return True;
}

// MAC conversions and checks
function mac2long($mac) {
    return hexdec(str_replace(':', '', $mac));
}

function long2mac($lmac, $sep=':') {
    $pmac = str_pad(dechex($lmac), 12, '0', STR_PAD_LEFT);
    return "{$pmac[0]}{$pmac[1]}$sep{$pmac[2]}{$pmac[3]}$sep{$pmac[4]}{$pmac[5]}$sep{$pmac[6]}{$pmac[7]}$sep{$pmac[8]}{$pmac[9]}$sep{$pmac[10]}{$pmac[11]}";
}

function valid_mac($mac, $part=6) {
    return preg_match('/^([a-f0-9]{2}\:?){'.$part.'}$/', strtolower($mac));
}

// Generate random key
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

// Convert num
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

// Convert seconds to text
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

    // remove leading ,
    return substr($output, 2);
}

// Write nets table
function write_nets($datas) {
    $has_input = False;
    echo '
<style type="text/css">
td {padding-left: 7px; padding-right: 7px}
</style>
<form class="form" method="post" action="?nets" enctype="multipart/form-data">
<table style="border: 1;">
<tr><th>BSSID</th><th>SSID</th><th>Type</th><th>WPA key</th><th>Get works</th><th>Timestamp</th></tr>';
    foreach ($datas as $data) {
        $bssid = long2mac($data['bssid']);
        $hash = $data['hash'];
        $ssid = htmlspecialchars($data['ssid']);
        if ($data['n_state'] == 0) {
            $pass = '<input class="input" type="text" name="'.$hash.'" size="20"/>';
            $has_input = True;
        } else {
            $pass = htmlspecialchars($data['pass']);
        }
        switch ($data['keyver']) {
            case 1:
                $type = 'WPA';
                break;
            case 2:
                $type = 'WPA2';
                break;
            case 3:
                $type = 'WPA2_11w';
                break;
            case 100:
                $type = 'PMKID';
                break;
            default:
                $type = 'UNC';
        }
        echo "<tr><td style=\"font-family:monospace; font-size: 12px; cursor: pointer; \"><a title=\"Wigle geo query. You must be logged in.\" href=\"https://wigle.net/search?netid=$bssid\">$bssid</a></td><td>$ssid</td><td>$type</td><td>$pass</td><td align=\"right\">{$data['hits']}</td><td>{$data['ts']}</td></tr>\n";
    }
    echo '</table>';
    if ($has_input) {
        echo '<input class="btn" type="submit" value="Send WPA keys" />';
    }
    echo '</form>';
}
?>
