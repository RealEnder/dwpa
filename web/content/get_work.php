<?php
// check incoming version string
if (version_compare($_GET['get_work'], MIN_HC_VER) < 0 ) {
    die('Version');
}

// check and validate options
if (! array_key_exists('options', $_POST)) {
    die('Version');
}

require_once('db.php');
require_once('common.php');

// Valid hex hash
function valid_hash($hash) {
    return preg_match('/^[a-f0-9]{32}$/', strtolower($hash));
}

// Associate handshakes to dict
function insert_n2d(& $mysql, & $ref) {
    if (count($ref) < 2) {
        return;
    }

    $bindvars = 'iis';
    $sql = 'INSERT INTO n2d(net_id, d_id, hkey) VALUES'.implode(',', array_fill(0, (count($ref)-1)/strlen($bindvars), '('.implode(',',array_fill(0, strlen($bindvars), '?')).')'));
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);

    $ref[0] = str_repeat($bindvars, (count($ref)-1)/strlen($bindvars));
    call_user_func_array(array($stmt, 'bind_param'), $ref);
    $stmt->execute();
    $stmt->close();
}

// this is for user supplied dictionary
$options = json_decode($_POST['options'], True);
if ($options && array_key_exists('ssid', $options)) {
    $stmt = $mysql->stmt_init();
    $stmt->prepare('SELECT HEX(ssid) AS ssid, hccapx
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
    // critical section begin
    create_lock('get_work.lock');

    // generate get_work key
    $hkey = gen_key();
    $bhkey = hex2bin($hkey);

    // get current dict
    $result = $mysql->query("SELECT d_id, HEX(dhash) as dhash, dpath
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
                  LIMIT 1");
    $dict = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();

    if (count($dict) == 0) {
        release_lock('get_work.lock');
        $mysql->close();
        die('No nets');
    }

    // add hkey and dict
    $resnet = array();
    $resnet[] = array('hkey' => $hkey);
    $resnet[] = array('dhash' => strtolower($dict[0]['dhash']));
    $resnet[] = array('dpath' => $dict[0]['dpath']);

    // get handshakes and prepare
    $stmt = $mysql->stmt_init();
    $stmt->prepare("SELECT net_id, hccapx
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
                     WHERE d_id=? AND
                           n2d.net_id = n.net_id)");
    $stmt->bind_param('i', $dict[0]['d_id']);
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
    foreach ($handshakes as $key => $handshake) {
        $resnet[] = array('hccapx' => base64_encode($handshake['hccapx']));
        $ref[] = & $handshakes[$key]['net_id'];
        $ref[] = & $dict[0]['d_id'];
        $ref[] = & $bhkey;
    }

    // populate in n2d
    insert_n2d($mysql, $ref);

    // critical section end
    release_lock('get_work.lock');
}

echo json_encode($resnet);
?>
