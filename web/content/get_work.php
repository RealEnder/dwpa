<?php
//check incoming version string
if (version_compare($_GET['get_work'], MIN_HC_VER) < 0 ) {
    die('Version');
}

//check and validate options
if (! array_key_exists('options', $_POST)) {
    die('Options');
}

require_once('db.php');
require_once('common.php');
    
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