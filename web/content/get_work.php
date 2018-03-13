<?php
//check incoming version string
if (version_compare($_GET['get_work'], MIN_HC_VER) < 0 ) {
    die('Version');
}

//check and validate options
if (! array_key_exists('options', $_POST)) {
    die('Version');
}

require_once('db.php');
require_once('common.php');

//valid hex hash
function valid_hash($hash) {
    return preg_match('/^[a-f0-9]{32}$/', strtolower($hash));
}

// Associate handshakes to dict
function insert_n2d(& $mysql, & $ref) {
    if (count($ref) < 2) {
        return;
    }

    $bindvars = 'iis';
    $sql = 'INSERT ignore INTO n2d(net_id, d_id, hkey) VALUES'.implode(',', array_fill(0, (count($ref)-1)/strlen($bindvars), '('.implode(',',array_fill(0, strlen($bindvars), '?')).')'));
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);

    $ref[0] = str_repeat($bindvars, (count($ref)-1)/strlen($bindvars));
    call_user_func_array(array($stmt, 'bind_param'), $ref);
    $stmt->execute();
    $stmt->close();
}

//this is for user supplied dictionary
$options = json_decode($_POST['options'], True);
if (array_key_exists('hash', $options)) {
    if (valid_hash($options['hash'])) {
        //this is for next uncracked net
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT HEX(hash) AS hash, bssid, hccapx FROM nets WHERE n_state=0 AND net_id > (SELECT net_id FROM nets WHERE hash=UNHEX(?)) ORDER BY net_id LIMIT 1');
        $stmt->bind_param('s', $options['hash']);
        $stmt->execute();
        $result = $stmt->get_result();
        $data = $result->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
    } else {
        //this is for initial start
        $result = $mysql->query('SELECT HEX(hash) AS hash, bssid, hccapx FROM nets WHERE n_state=0 ORDER BY net_id LIMIT 1');
        $data = $result->fetch_all(MYSQLI_ASSOC);
    }
    $result->free();

    if (count($data) != 1) {
        die('No nets!?');
    }
    $data = $data[0];
    $resnet = array();

    $json = array();
    $json['hash']  = strtolower($data['hash']);
    $json['bssid']  = long2mac($data['bssid']);
    $json['hccapx']  = base64_encode($data['hccapx']);
    $resnet[] = $json;
} else {
    // critical section begin
    create_lock('get_work.lock');

    // generate get_work key
    $hkey = gen_key();
    $bhkey = hex2bin($hkey);

    // get current dict
    $result = $mysql->query('SELECT * FROM get_dict LIMIT 1');
    $dict = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();

    // add hkey and dict
    $resnet = array();
    $resnet[] = array('hkey' => $hkey);
    $resnet[] = array('dhash' => strtolower($dict[0]['dhash']));
    $resnet[] = array('dpath' => $dict[0]['dpath']);

    // get handshakes and prepare
    $result = $mysql->query('SELECT * FROM onets');
    $handshakes = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();

    $ref = array('');
    foreach ($handshakes as $key => $handshake) {
        $resnet[] = array('hash' => strtolower($handshake['hash']),
                          'bssid' => long2mac($handshake['bssid']),
                          'hccapx' => base64_encode($handshake['hccapx']));
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
