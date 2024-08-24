<?php
// Implements hashcat $HEX[]
function hc_unhex($key) {
    if (strlen($key) <= 6) {
        return $key;
    }

    $k = substr($key, 5, -1);
    if (( (bool) (~ strlen($k) & 1)) &&
        str_starts_with($key, '$HEX[') &&
        str_ends_with($key, ']') &&
        (ctype_xdigit($k))) {

        return hex2bin($k);
    }

    if ( $k == '' &&
        str_starts_with($key, '$HEX[') &&
        str_ends_with($key, ']')) {

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

// Build candidates array from browser submissions
function build_cand($inarr) {
    if (!empty($inarr)) {
        $arr = ['type' => 'hash',
                'cand' => []
               ];

        foreach ($inarr as $k=>$v) {
            $arr['cand'][] = ['k'=>$k, 'v'=>$v];
        }

        return $arr;
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
    $keys      = [];
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
hashline format:
SIGNATURE*TYPE*PMKID/MIC*MACAP*MACSTA*ESSID*ANONCE*EAPOL*MESSAGEPAIR/PMKID INFO

    SIGNATURE = "WPA"
    TYPE = 01 for PMKID, 02 for EAPOL, others to follow
    PMKID/MIC = PMKID if TYPE==01, MIC if TYPE==02
    MACAP = MAC of AP
    MACSTA = MAC of station
    ESSID = ESSID
    ANONCE = ANONCE
    EAPOL = EAPOL (SNONCE is in here)
    MESSAGEPAIR = Bitmask:
0: MP info (https://hashcat.net/wiki/doku.php?id=hccapx)*
1: MP info (https://hashcat.net/wiki/doku.php?id=hccapx)*
2: MP info (https://hashcat.net/wiki/doku.php?id=hccapx)*
3: x (unused)
4: ap-less attack (set to 1) - no nonce-error-corrections necessary
5: LE router detected (set to 1) - nonce-error-corrections only for LE necessary
6: BE router detected (set to 1) - nonce-error-corrections only for BE necessary
7: not replaycount checked (set to 1) - replaycount not checked, nonce-error-corrections definitely necessary
    *
000 = M1+M2, EAPOL from M2 (challenge)
001 = M1+M4, EAPOL from M4 (authorized)
010 = M2+M3, EAPOL from M2 (authorized)
011 = M2+M3, EAPOL from M3 (authorized)
100 = M3+M4, EAPOL from M3 (authorized)
101 = M3+M4, EAPOL from M4 (authorized)
    PMKID INFO = For type 01, bitmask:
0: reserved
1: PMKID taken from AP
2: reserved
3: reserved
4: PMKID taken from CLIENT (wlan.da: possible MESH or REPEATER)
5: reserved
6: reserved
7: reserved

Return value:
False - Not cracked
[PSK, NC, BE/LE, PMK]
*/

function check_key_m22000($hashline, $keys, $pmk=False, $nc=128) {
    // split and check
    $ahl = explode('*', $hashline, 9);
    if (count($ahl) != 9) return False;
    if ($ahl[0] != 'WPA') return False;
    if (valid_hex($ahl[3])) $mac_ap  = hex2bin($ahl[3]); else return False;
    if (valid_hex($ahl[4])) $mac_sta = hex2bin($ahl[4]); else return False;
    if (valid_hex($ahl[5])) $essid   = hex2bin($ahl[5]); else return False;

    // PMKID
    if ($ahl[1] == '01') {
        // unhex
        if (valid_hex($ahl[2])) $pmkid = hex2bin($ahl[2]); else return False;

        foreach ($keys as $key) {
            // TODO: find-out why we have Nulls here
            if (is_null($key)) continue;
            if (str_starts_with($key, '$HEX[')) {
                $key = hc_unhex($key);
            }

            if (!$pmk) {
                $pmk = openssl_pbkdf2($key, $essid, 32, 4096, 'sha1');
            }

            // compute PMKID candidate
            $testpmkid = hash_hmac('sha1', 'PMK Name' . $mac_ap . $mac_sta, $pmk, True);

            if (strncmp($testpmkid, $pmkid, 16) == 0) {
                return [$key, Null, Null, $pmk];
            }
            $pmk = False;
        }
    // handshake
    } elseif ($ahl[1] == '02') {
        if (valid_hex($ahl[2])) $keymic   = hex2bin($ahl[2]); else return False;
        if (valid_hex($ahl[6])) $nonce_ap = hex2bin($ahl[6]); else return False;
        if (valid_hex($ahl[7])) $eapol    = hex2bin($ahl[7]); else return False;
        if (valid_hex($ahl[8])) $mp       = hex2bin($ahl[8]); else return False;
        /*
        struct auth_packet
        {
          u8  version;
          u8  type;
          u16 length;
          u8  key_descriptor;
          u16 key_information;
          u16 key_length;
          u64 replay_counter;
          u8  wpa_key_nonce[32];
          u8  wpa_key_iv[16];
          u8  wpa_key_rsc[8];
          u8  wpa_key_id[8];
          u8  wpa_key_mic[16];
          u16 wpa_key_data_length;

        } __attribute__((packed));
        */
        $aeapol = unpack('x5/nkey_information/x10/a32nonce_sta', $eapol);
        $nonce_sta = $aeapol['nonce_sta'];
        $keyver = $aeapol['key_information'] & 3;

        // fix order
        if (strncmp($mac_ap, $mac_sta, 6) < 0)
            $m = $mac_ap.$mac_sta;
        else
            $m = $mac_sta.$mac_ap;

        $swap = False;
        if (strncmp($nonce_sta, $nonce_ap, 6) < 0)
            $n = $nonce_sta.$nonce_ap;
        else {
            $n = $nonce_ap.$nonce_sta;
            $swap = True;
        }

        // get nonce_ap last bytes for nonce correction
        $corr['V'] = unpack('x28/V', $nonce_ap)[1];
        $corr['N'] = unpack('x28/N', $nonce_ap)[1];

        $halfnc = ($nc >> 1) + 1;

        foreach ($keys as $key) {
            // TODO: find-out why we have Nulls here
            if (is_null($key)) continue;
            if (str_starts_with($key, '$HEX[')) {
                $key = hc_unhex($key);
            }

            if (!$pmk) {
                $pmk = openssl_pbkdf2($key, $essid, 32, 4096, 'sha1');
            }

            $ncarr = [['N', 0]];
            do {
                foreach ($ncarr as $j) {
                    $rawlast = pack($j[0], $corr[$j[0]] + $j[1]);

                    if ($swap) {
                        $n = substr_replace($n, $rawlast, 28, 4);
                    } else {
                        $n = substr_replace($n, $rawlast, 60, 4);
                    }

                    switch ($keyver) {
                        case 1:
                            $ptk = hash_hmac('sha1', "Pairwise key expansion\0" . $m . $n . "\0", $pmk, True);
                            $testmic = hash_hmac('md5',  $eapol, substr($ptk, 0, 16), True);
                            break;
                        case 2:
                            $ptk = hash_hmac('sha1', "Pairwise key expansion\0" . $m . $n . "\0", $pmk, True);
                            $testmic = hash_hmac('sha1', $eapol, substr($ptk, 0, 16), True);
                            break;
                        case 3:
                            $ptk = hash_hmac('sha256', "\1\0Pairwise key expansion" . $m . $n . "\x80\1", $pmk, True);
                            $testmic = omac1_aes_128($eapol, substr($ptk, 0, 16));
                            break;
                        default:
                            // unknown keyver
                            return False;
                    }

                    if (strncmp($testmic, $keymic, 16) === 0) {
                        if ($ncarr[0][1] == 0) {
                            return [$key, 0, Null, $pmk];
                        } else {
                            if ($j[0] == 'N') {
                                return [$key, $j[1], 'BE', $pmk];
                            } else {
                                return [$key, $j[1], 'LE', $pmk];
                            }
                        }

                    }
                }
                if ($ncarr[0][1] == 0) {
                    $ncarr = [['V', 1], ['V', -1], ['N', 1], ['N', -1]];
                } else {
                    $ncarr[0][1]++;
                    $ncarr[1][1]--;
                    $ncarr[2][1]++;
                    $ncarr[3][1]--;
                }
            } while ($ncarr[0][1] <= $halfnc);

            $pmk = False;
        }
    }

    return False;
}

// Extract md5 hash over partial m22000 struct
function hash_m22000($hashline) {
    $ahl = explode('*', $hashline, 9);
    if (count($ahl) != 9) return False;

    return hash('md5', $ahl[1].$ahl[2].$ahl[3].$ahl[4].$ahl[5].$ahl[6].$ahl[7], True);
}

// Create filesystem lock file or wait until we can create one
// Proceed if the lockfile is older than 1 minute
// TODO: use flock()
function create_lock($lockfile) {
    while (file_exists(SHM . $lockfile) && (time() - filemtime(SHM . $lockfile) <= 60)) {
        sleep(1);
    }
    touch(SHM.$lockfile);
}

// Release filesystem lock file if exists
function release_lock($lockfile) {
    if (file_exists(SHM . $lockfile)) {
        @unlink(SHM . $lockfile);
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
    $sql = 'SELECT hash FROM nets WHERE hash IN (' . implode(',', array_fill(0, count($ref) - 1, '?')) . ')';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);

    $ref[0] = str_repeat('s', count($ref) - 1);
    call_user_func_array([$stmt, 'bind_param'], $ref);
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
    call_user_func_array([$stmt, 'bind_param'], $ref);
    $stmt->execute();
    $stmt->close();
}

// Associate handshake to user
function insert_n2u(& $mysql, & $ref, $u_id) {
    if (count($ref) < 2) {
        return;
    }

    $sql = "INSERT IGNORE INTO n2u(net_id, u_id) SELECT net_id, $u_id FROM nets WHERE hash IN (" . implode(',', array_fill(0, count($ref) - 1, '?')) . ')';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);

    $ref[0] = str_repeat('s', count($ref) - 1);
    call_user_func_array([$stmt, 'bind_param'], $ref);
    $stmt->execute();
    $stmt->close();
}

// Get u_id by userkey
function get_u_id_by_userkey(& $mysql, $userkey) {
    if (!valid_key($userkey)) return Null;

    $u_id = Null;
    $stmt = $mysql->stmt_init();
    $stmt->prepare('SELECT u_id FROM users WHERE userkey=UNHEX(?)');
    $stmt->bind_param('s', $userkey);
    $stmt->execute();
    $stmt->bind_result($u_id);
    $stmt->fetch();
    $stmt->close();

    return $u_id;
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

    // extract WPA-PBKDF2-PMKID+EAPOL hash file from uploaded capture
    $m22000file = tempnam(SHM, '22000');
    $res = '';
    $rc  = 0;
    exec(HCXPCAPTOOL." --nonce-error-corrections=8 --eapoltimeout=20000 --max-essids=1 -o $m22000file $file 2>&1", $res, $rc);

    if ($rc != 0) {
        @unlink($file);
        return "Capture processing error. Exit code $rc. Please inform developers.";
    }

    // add submission
    if (file_exists($m22000file)) {
        // compute hash and create new capture name
        $partial_path = date('Y/m/d/');
        $md5 = hash_file('md5', $file, True);
        $capfile = CAP . $partial_path . $_SERVER['REMOTE_ADDR'] . '-' . bin2hex($md5) . '.cap';

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
            if (!is_dir(CAP . $partial_path)) {
                mkdir(CAP . $partial_path, 0777, True);
            }

            chmod($file, 0644);
            move_uploaded_file($file, $capfile);
        }

        $userkey = (isset($_COOKIE['key']) && valid_key($_COOKIE['key'])) ? $_COOKIE['key'] : '';
        if ($s_id == False && $userkey == '') {
            @unlink($m22000file);
            return 'This capture file was already submitted.';
        }
    } else {
        @unlink($file);
        return 'No valid handshakes/PMKIDs found in the submitted file.';
    }

    $nets = [];
    $ref = [''];

    // read m22000 hash file
    $fp = fopen($m22000file, 'r');
    while ($hashline = fgets($fp)) {
        $hashline = rtrim($hashline);
        // validate m22000 hash line
        if (!str_starts_with($hashline, 'WPA*')) return False;
        if (substr_count($hashline, '*') < 8) return False;

        $hash = hash_m22000($hashline);
        if (isset($nets[$hash])) {
            continue;
        }

        $nets[$hash] = [$hash, $hashline];
        $ref[] = & $nets[$hash][0];
        if (count($ref) > 1000) {
            duplicate_nets($mysql, $ref, $nets);
            $ref = [''];
        }
    }
    fclose($fp);
    @unlink($m22000file);
    duplicate_nets($mysql, $ref, $nets);
    $ref = [''];

    // insert identified hashes
    $zpmk = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    $pmkarr = [];
    if ($s_id) {
        $refi = [''];
        $hs_stmt = Null;
        foreach ($nets as &$net) {
            // do we have a skip mark?
            if (array_key_exists(100, $net)) {
                continue;
            }

            // parse m22000 hashline
            // SIGNATURE*TYPE*PMKID/MIC*MACAP*MACSTA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
            // 0         1    2         3     4      5     6      7     8
            $ahl = explode('*', $net[1], 9);

            $mac_ap  = hexdec($ahl[3]);
            $mac_sta = hexdec($ahl[4]);
            $essid   = hex2bin($ahl[5]);

            $message_pair = hexdec($ahl[8]);
            $keyver       = 100;

            if ($ahl[1] == '02') {
                // this is handshake
                $keyver = hexdec(substr($ahl[7], 12, 2)) & 3;
            }

            $net[2] = $mac_ap;
            $net[3] = $essid;
            $net[4] = $message_pair;
            $net[5] = $keyver;
            $net[6] = $mac_sta;

            // check for zeroed PMK
            $reshs = check_key_m22000($net[1], [''], $zpmk);
            if ($reshs) {
                // this is zeroed PMK
                $pmkarr[$net[0]] = ['key'    => '',
                                    'pmk'    => $zpmk,
                                    'nc'     => $reshs[1],
                                    'endian' => $reshs[2],
                                    'sip'    => 2130706433,
                                    'algo'   => 'ZeroPMK'];
            } else {
                // look for cracked handshakes/PMKIDs with same features and try to crack current by PMK
                $broken_essid = False;
                $hss = get_handshakes($mysql, $hs_stmt, $essid, $mac_ap, $mac_sta, 1);
                foreach ($hss as $hs) {
                    $reshs = check_key_m22000($net[1], [$hs['pass']], $hs['pmk'], (abs((int) $hs['nc']) << 1) + 1);
                    if ($reshs) {
                        // we cracked that by PMK, now let's check if essid matches
                        // if this not pass, we have broken essid and we'll skip this net.
                        if ($essid === $hs['ssid']) {
                            $pmkarr[$net[0]] = ['key'    => $reshs[0],
                                                'pmk'    => $hs['pmk'],
                                                'nc'     => $reshs[1],
                                                'endian' => $reshs[2],
                                                'sip'    => $hs['sip'],
                                                'algo'   => $hs['algo']];
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
                $refi = [''];
            }
        }
        if ($hs_stmt) {
            $hs_stmt->close();
        }
        insert_nets($mysql, $refi);
        $refi = [''];

    }

    // associate nets to user if we have key submitted
    if ($u_id = get_u_id_by_userkey($mysql, $userkey)) { // this have to be assignment
        $ref = [''];
        foreach ($nets as $net) {
            $ref[] = & $net[0];
            if (count($ref) > 1000) {
                insert_n2u($mysql, $ref, $u_id);
                $ref = [''];
            }
        }
        insert_n2u($mysql, $ref, $u_id);
        $ref = [];
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

    // update net stats
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
        $stmt->prepare('SELECT net_id, struct, ssid, bssid, mac_sta FROM nets WHERE bssid = ? AND n_state=0');
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
        $stmt->prepare('SELECT net_id, struct, ssid, bssid, mac_sta FROM nets WHERE hash = UNHEX(?) AND n_state=0');
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
        $stmt->prepare('SELECT net_id, struct, ssid, bssid, mac_sta FROM nets WHERE ssid = UNHEX(?) AND n_state=0');
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
                // submit the found PSK
                if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
                    $iip = ip2long($_SERVER['REMOTE_ADDR']);
                } else {
                    $iip = 2130706433;
                }

                submit_by_net_id($mysql, $submit_stmt, $res[0], $res[3], $res[1], $res[2], $iip, $net['net_id']);
                delete_from_n2d($mysql, $n2d_stmt, $net['net_id']);

                // check for other crackable nets with this PMK
                $broken_essid = False;
                $hss = get_handshakes($mysql, $hs_stmt, $net['ssid'], $net['bssid'], $net['mac_sta'], 0);
                foreach ($hss as $hs) {
                    if ($hs['keyver'] == 100) {
                        $reshs = check_key_pmkid($hs['struct'], array($key), $res[3]);
                    } else {
                        $reshs = check_key_hccapx($hs['struct'], array($key), abs((int) $res[1])*2+128, $res[3]);
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
    // TODO: replace this with SELECT n_state, keyver, count(distinct bssid), count(net_id), count(distinct ssid) FROM nets USE INDEX (IDX_nets_keyver_n_state) group by n_state, keyver; + CASE multiple update
    // TODO: all below have to move to external stats generator
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE n_state=1) WHERE pname='cracked'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1) WHERE pname='cracked_unc'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE n_state=1 AND keyver=100) WHERE pname='cracked_pmkid'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1 AND keyver=100) WHERE pname='cracked_pmkid_unc'");

    // pull cracked wordlist
    $stmt = $mysql->stmt_init();
    $stmt->prepare("SELECT pass
FROM (SELECT DISTINCT ssid, pass
      FROM nets
      WHERE n_state=1 AND
      (algo IS NULL OR algo = '')) t
GROUP BY pass
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
    gzclose($fd);

    $md5 = hash_file('md5', $wpakeys, True);
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

// TODO: Remove mac2long() and long2mac() functions
// MAC conversions and checks
function mac2long($mac) {
    return hexdec(str_replace(':', '', $mac));
}

function long2mac($lmac) {
    return sprintf('%012x', $lmac);
}

function valid_mac($mac, $part=6) {
    return preg_match('/^([a-f0-9]{2}\:?){'.$part.'}$/', strtolower($mac));
}

// Generate random key
function gen_key() {
    return bin2hex(random_bytes(16));
}

// Validate e-mail + MX
function validEmail($email) {
    $email = trim($email);

    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $domain = substr(strrchr($email, '@'), 1);
        if (checkdnsrr($domain.'.', 'MX')) {
            return True;
        }
    }

    return False;
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
    $units = [
        'year'   => 29030400, // seconds in a year   (12 months)
        'month'  => 2419200,  // seconds in a month  (4 weeks)
        'day'    => 86400,    // seconds in a day    (24 hours)
        'hour'   => 3600      // seconds in an hour  (60 minutes)
    ];
    $output='';

    foreach($units as $unit => $mult)
        if($secs >= $mult) {
            $and = (($mult != 1) ? ('') : ('and '));
            $output .= ', ' . $and . intval($secs / $mult) . ' ' . $unit . ((intval($secs / $mult) == 1) ? ('') : ('s'));
            $secs -= intval($secs / $mult) * $mult;
        }

    // remove leading ,
    return substr($output, 2);
}

// Decode keyver values
function decode_keyver($keyver) {
    switch ($keyver) {
        case 1:
            return 'WPA';
        case 2:
            return 'WPA2';
        case 3:
            return 'WPA2_11w';
        case 100:
            return 'PMKID';
        default:
            return 'UNC';
    }
}

// Decode message_pair/PMKID type values
function decode_mp($mp, $keyver) {
    $res = '';
    $mp = (int) $mp;

    if ($keyver == 100) {
        switch (True) {
            case $mp & 0x01:
                $res = 'AP';
                break;
            case $mp & 0x10:
                $res = 'CL';
                break;
            default:
                $res = 'UNK';
        }
    } else {
        switch (True) {
            case ($mp & 0b111) == 0:
                $res = 'M1M2/M2/U';
                break;
            case $mp & 0b001:
                $res = 'M1M4/M4/A';
                break;
            case $mp & 0b010:
                $res = 'M2M3/M2/A';
                break;
            case $mp & 0b011:
                $res = 'M2M3/M3/A';
                break;
            case $mp & 0b100:
                $res = 'M3M4/M3/A';
                break;
            case $mp & 0b101:
                $res = 'M3M4/M4/A';
                break;
            default:
                $res = 'UNK';
        }
        if ($mp & 0b00010000) $res .= ' AP-less';
        if ($mp & 0b10000000) $res .= ' RCnC';
        if ($mp & 0b00100000) $res .= ' LE';
        if ($mp & 0b01000000) $res .= ' BE';
    }

    return $res;
}

// Construct Key info data
function decode_keyinfo($n_state, $algo, $nc, $endian) {
    if ($n_state == 2) return 'Uncrackable';

    $res = '';
    if ($algo != Null)   $res .= $algo;
    if ($nc != 0)        $res .= " nc: $nc";
    if ($endian != Null) $res .= " $endian";

    return $res;
}

// Write nets table
function write_nets($datas) {
    $has_input = False;
    echo '
<form class="form" method="post" action="?nets">
<table class="nets">
<tr><th>CC</th><th>BSSID</th><th>SSID</th><th>Type</th><th>Feat</th><th>WPA key</th><th>Key info</th><th>Get works</th><th>Timestamp</th></tr>
';
    foreach ($datas as $data) {
        $bssid = long2mac($data['bssid']);
        $hash = $data['hash'];
        $ssid = htmlspecialchars($data['ssid']);
        if ($data['n_state'] == 0) {
            $pass = "<input class=\"input\" name=\"$hash\">";
            $has_input = True;
        } else {
            $pass = htmlspecialchars($data['pass']);
        }
        $type = decode_keyver($data['keyver']);
        $feat = decode_mp($data['message_pair'], $data['keyver']);
        $keyinfo = decode_keyinfo($data['n_state'], $data['algo'], $data['nc'], $data['endian']);

        if (array_key_exists('country', $data) && $data['country'] != Null) {
            $data['country'] = strtolower($data['country']);
        } else {
            $data['country'] = 'xx';
        }

        echo "<tr><td><span class=\"fi fi-{$data['country']} fi\" title=\"{$data['country']}\"></span></td><td class=\"bssid\">$bssid</td><td>$ssid</td><td>$type</td><td>$feat</td><td>$pass</td><td>$keyinfo</td><td>{$data['hits']}</td><td>{$data['ts']}</td></tr>\n";
    }
    echo '</table>
<script>
function attachLinksToBssid() {
    const baseURL = "https://wigle.net/search?netid=";
    const bssidCells = document.querySelectorAll("td.bssid");
    bssidCells.forEach(cell => {
        const bssidValue = cell.textContent.trim();
        const link = document.createElement("a");
        link.href = baseURL + encodeURIComponent(bssidValue.match(/.{1,2}/g).join(":"));
        link.title = "Wigle geo query. You must be logged in.";
        link.textContent = bssidValue;
        cell.textContent = "";
        cell.appendChild(link);
    });
}

attachLinksToBssid();
</script>
';
    if ($has_input) {
        echo '<br><input class="btn" type="submit" value="Send WPA keys">';
    }
    echo '</form>';
}
?>
