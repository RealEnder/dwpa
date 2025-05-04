<?php
// run this only via cli
if (php_sapi_name() !== 'cli') {
    die('Run this from cli');
}

require('conf.php');
require('db.php');
require('common.php');

function update_nets_algo(& $mysql, & $stmt, $algo, $net_id) {
    if ($stmt == Null) {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('UPDATE nets SET algo=? WHERE net_id=?');
    }

    $stmt->bind_param('si', $algo, $net_id);
    $stmt->execute();
}

function single_mode_generator($bssid, $ssid) {
    $res = [];

    // bssid gen
    for ($i=-16; $i<=16; $i++) {
        foreach ([12, 10, 8] as $j) {
            $curr = substr(dechex($bssid + $i), -$j);
            $res[] = str_pad(           $curr , $j, '0', STR_PAD_LEFT);
            $res[] = str_pad(strtoupper($curr), $j, '0', STR_PAD_LEFT);
        }
    }

    // ssid gen
    foreach (['', '1', '123', '!'] as $j) {
        $can = $ssid.$j;
        if (strlen($can) >= 8) {
            $canuc = strtoupper($can);
            $canlc = strtolower($can);
            $res[] = $can;
            if ($can != $canuc) {
                $res[] = $canuc;
            }
            if ($can != $canlc) {
                $res[] = $canlc;
            }
        }
    }

    return $res;
}

$submit_stmt = Null;
$update_stmt = Null;

$regenerate_rkg_dict = False;

// Fetch unchecked networks
$result = $mysql->query('SELECT net_id, struct, ssid, bssid, pass, hits FROM nets WHERE algo IS NULL ORDER BY net_id LIMIT 100');
$nets = $result->fetch_all(MYSQLI_ASSOC);
$result->free();

foreach ($nets as $netkey => $net) {
    if (ctype_print($net['ssid'])) {
        $cleanssid = $net['ssid'];
    } else {
        $cleanssid = '';
    }

    $algo = '';
    $candidates = [];
    $cres = False;
    $res = '';
    $rc  = 0;
    $mac = implode(':', str_split(long2mac($net['bssid']), 2));

    exec(RKG." -q -k -m $mac -s ".escapeshellarg($cleanssid), $res, $rc);

    if ($rc == 0) {
        // process rkg output
        foreach ($res as $line) {
            if (! ($candidates[] = explode(':', $line, 2)) || count(end($candidates)) != 2 ) {
                array_pop($candidates);
            } else {
                // fill reference array and verify if this net was cracked
                $key = key($candidates);
                if ($candidates[$key][1] == $net['pass'] || ($cres = check_key_m22000($net['struct'], [$candidates[$key][1]]))) {
                    $algo = $candidates[$key][0];
                    break;
                }
            }
        }

        // update PSK found if cracked, submitter IP is 127.0.0.1
        if ($cres) {
            submit_by_net_id($mysql, $submit_stmt, $cres[0], $cres[3], $cres[1], $cres[2], 2130706433, $net['net_id']);
        }
    }

    // single mode crack
    if ($algo == '') {
        $res = single_mode_generator($net['bssid'], $net['ssid']);
        if ($cres = check_key_m22000($net['struct'], $res)) {
            submit_by_net_id($mysql, $submit_stmt, $cres[0], $cres[3], $cres[1], $cres[2], 2130706433, $net['net_id']);
            $algo = 'Single';
        }
    }

    // set algo name or just empty if not identified
    update_nets_algo($mysql, $update_stmt, $algo, $net['net_id']);

    if ($algo != '') {
        $regenerate_rkg_dict = True;
    }
}

// cleanup DB connections
if ($submit_stmt) {
    $submit_stmt->close();
}
if ($update_stmt) {
    $update_stmt->close();
}

// regenerate rkg.txt.gz if we have hit
if ($regenerate_rkg_dict) {
    // pull rkg cracked wordlist
    $stmt = $mysql->stmt_init();
    $stmt->prepare("SELECT DISTINCT pass FROM nets WHERE algo IS NOT NULL AND algo != ''");
    $stmt->execute();
    $stmt->bind_result($key);

    //write compressed rkg wordlist
    $wpakeys = tempnam(SHM, 'rkgkeys');
    chmod($wpakeys, 0644);
    $fd = gzopen($wpakeys, 'wb9');
    while ($stmt->fetch()) {
        gzwrite($fd, "$key\n");
    }
    $stmt->close();
    fflush($fd);
    gzclose($fd);

    rename($wpakeys, dirname(CRACKED).'/rkg.txt.gz');

    // update statistics
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE algo IS NOT NULL AND algo != '') WHERE pname='cracked_rkg'");
    $mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE algo IS NOT NULL AND algo != '') WHERE pname='cracked_rkg_unc'");
}

$mysql->close();
?>
