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
    $mysql->close();

    if (count($data) != 1) {
        die('No nets!?');
    }
    $data = $data[0];

    $json = array();
    $json['hash']  = strtolower($data['hash']);
    $json['bssid']  = long2mac($data['bssid']);
    $json['hccapx']  = base64_encode($data['hccapx']);

    echo json_encode($json);
    exit();
}

//get next handshake/dict pair
$result = $mysql->query('SELECT * FROM (SELECT * FROM onets LIMIT 1) a, (SELECT * FROM get_dict LIMIT 1) b');
$data = $result->fetch_all(MYSQLI_ASSOC);
$result->free();

if (count($data) != 1) {
    $mysql->close();
    die('No nets!?');
}
$data = $data[0];

//mark handshake/dict pair as returned for cracking
$usql = 'INSERT INTO n2d(net_id, d_id) VALUES(?, ?) ON DUPLICATE KEY UPDATE Hits=Hits+1, ts=NOW()';
$ustmt = $mysql->stmt_init();
$ustmt->prepare($usql);
$ustmt->bind_param('ii', $data['net_id'], $data['d_id']);
$ustmt->execute();
$ustmt->close();
$mysql->close();

//return to client
$json = array();
$json['hash']  = strtolower($data['hash']);
$json['bssid']  = long2mac($data['bssid']);
$json['dpath']  = $data['dpath'];
$json['dhash']  = strtolower($data['dhash']);
$json['hccapx']  = base64_encode($data['hccapx']);

echo json_encode($json);
?>
