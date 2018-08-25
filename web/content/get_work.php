<?php
// check incoming version string
if (version_compare($_GET['get_work'], MIN_HC_VER) < 0 ) {
    die('Version');
}

// check and validate options
if (! array_key_exists('options', $_POST)) {
    die('Version');
}

require_once('../db.php');
require_once('../common.php');

// Valid hex hash
function valid_hash($hash) {
    return preg_match('/^[a-f0-9]{32}$/', strtolower($hash));
}

// Exctract essid from hccapx or PMKID structs
function get_essid($net) {
    if ($net['keyver'] == 100) {
        $apmkid = explode('*', $net['struct'], 4);
        return hex2bin($apmkid[3]);
    } else {
        // TODO: fix this bloody sht
        $essid_len = ord(substr($net['struct'], 0x09, 1));
        if (version_compare(PHP_VERSION, '5.5.0') >= 0) {
            $essid = unpack('Z32', substr($net['struct'], 0x0a, 32));
        } else {
            $essid = unpack('a32', substr($net['struct'], 0x0a, 32));
        }
        return substr($essid[1], 0, $essid_len);
    }
}

// Associate handshakes to dict
function insert_n2d(& $mysql, & $ref) {
    if (count($ref) < 2) {
        return;
    }

    $bindvars = 'iis';
    $sql = 'INSERT IGNORE INTO n2d(net_id, d_id, hkey) VALUES'.implode(',', array_fill(0, (count($ref)-1)/strlen($bindvars), '('.implode(',',array_fill(0, strlen($bindvars), '?')).')'));
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);

    $ref[0] = str_repeat($bindvars, (count($ref)-1)/strlen($bindvars));
    call_user_func_array(array($stmt, 'bind_param'), $ref);
    $stmt->execute();
    $stmt->close();
}

// this is for user supplied dictionary
$options = json_decode($_POST['options'], True);
if (!is_array($options) || json_last_error() !== JSON_ERROR_NONE) {
    die('Options');
}
if (array_key_exists('ssid', $options)) {
    $stmt = $mysql->stmt_init();
    $stmt->prepare('SELECT HEX(ssid) AS ssid, struct, keyver
FROM nets
WHERE n_state=0 AND
      ssid = BINARY (SELECT BINARY ssid
                     FROM nets
                     WHERE n_state=0 AND
                           ssid > UNHEX(?)
                     GROUP BY BINARY ssid ASC
                     LIMIT 1)');
    $stmt->bind_param('s', $options['ssid']);
    $stmt->execute();
    $result = $stmt->get_result();
    $handshakes = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    $result->free();

    if (count($handshakes) == 0) {
        $mysql->close();
        die('No nets');
    }

    $resnet = array();
    $resnet[] = array('ssid' => $handshakes[0]['ssid']);
    foreach ($handshakes as $key => $handshake) {
        $resnet[] = array('hccapx' => base64_encode($handshake['hccapx']));
    }
} else {
    // check desired dict count
    $dictcount = 1;
    if ($options && array_key_exists('dictcount', $options)) {
        $dictcount = filter_var($options['dictcount'],
                                FILTER_VALIDATE_INT,
                                array('default' => 1, 'min_range' => 1, 'max_range' => 15));
    }

    // critical section begin
    create_lock('get_work.lock');

    // generate get_work key
    $hkey = gen_key();
    $bhkey = hex2bin($hkey);

    // get current dict
    $stmt = $mysql->stmt_init();
    $stmt->prepare("SELECT d_id, HEX(dhash) as dhash, dpath
FROM dicts d
WHERE NOT EXISTS (SELECT d_id
                  FROM n2d
                  WHERE d.d_id=n2d.d_id AND
                        n2d.net_id=(SELECT net_id
                                    FROM nets
                                    WHERE n_state=0 AND
                                          algo=''
                                    ORDER BY hits, ts
                                    LIMIT 1))
ORDER BY d.wcount, d.dname
LIMIT ?");
    $stmt->bind_param('i', $dictcount);
    $stmt->execute();
    $result = $stmt->get_result();
    $dicts = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();
    $dc = count($dicts);

    if ($dc == 0) {
        release_lock('get_work.lock');
        $mysql->close();
        die('No nets');
    }

    // add hkey and dict
    // TODO: move single dict into dicts arr and increment API version
    $resnet = array();
    $ref = array('');
    $resnet[] = array('hkey' => $hkey);
    if ($dc == 1) {
        $resnet[] = array('dhash' => strtolower($dicts[0]['dhash']));
        $resnet[] = array('dpath' => $dicts[0]['dpath']);
        $ref[] = & $dicts[0]['d_id'];
    } else {
        $jdicts = array();
        for ($i = 0; $i < $dc; $i++) {
            $jdicts[] = array('dhash' => strtolower($dicts[$i]['dhash']), 'dpath' => $dicts[$i]['dpath']);
            $ref[] = & $dicts[$i]['d_id'];
        }
        $resnet[] = array('dicts' => $jdicts);
    }

    // get handshakes and prepare
    $stmt = $mysql->stmt_init();
    $stmt->prepare("SELECT net_id, struct, keyver
FROM nets n
WHERE ssid = BINARY (SELECT ssid
                     FROM nets
                     WHERE n_state=0 AND
                           algo=''
                     ORDER BY hits, ts
                     LIMIT 1) AND
      n_state=0 AND
      algo='' AND
      net_id NOT IN (SELECT net_id
                     FROM n2d
                     WHERE d_id IN (".implode(',', array_fill(0, $dc, '?')).") AND
                           n2d.net_id = n.net_id)");
    $ref[0] = str_repeat('i', $dc);
    call_user_func_array(array($stmt, 'bind_param'), $ref);
    $stmt->execute();
    $result = $stmt->get_result();
    $handshakes = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();

    if (count($handshakes) == 0) {
        release_lock('get_work.lock');
        $mysql->close();
        die('No nets');
    }

    $ref = array('');
    $essid = get_essid($handshakes[0]);
    foreach ($handshakes as $key => $handshake) {
        // TODO: essid compare here will be unneeded when we move to binary storage
        $curr_essid = get_essid($handshake);
        if ($essid === $curr_essid) {
            if ($handshake['keyver'] == 100) {
                $resnet[] = array('pmkid' => $handshake['struct']);
            } else {
                $resnet[] = array('hccapx' => base64_encode($handshake['struct']));
            }
            for ($i = 0; $i < $dc; $i++) {
                $ref[] = & $handshakes[$key]['net_id'];
                $ref[] = & $dicts[$i]['d_id'];
                $ref[] = & $bhkey;
            }
        }
    }

    // populate in n2d
    insert_n2d($mysql, $ref);

    // critical section end
    release_lock('get_work.lock');
}

echo json_encode($resnet);
?>
