<?
require('db.php');
require('common.php');

//Get work
$sql = 'SELECT * FROM onets, get_dict LIMIT 1';
$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$data = array();
stmt_bind_assoc($stmt, $data);
$stmt->execute();

if ($stmt->fetch()) {
    $stmt->free_result();

    if ($_GET['get_work'] == 'no_dict') {
        //Return net, to break with local dict
        $usql = 'UPDATE nets SET hits=hits+1 WHERE bssid=?';
        $ustmt = $mysql->stmt_init();
        $ustmt->prepare($usql);
        $ustmt->bind_param('i', $data['bssid']);
        $ustmt->execute();
        $ustmt->close();
        echo long2mac($data['bssid']);
    } else {
        //Return net+dict
        $usql = 'INSERT INTO n2d(bssid, d_id) VALUES(?, ?) ON DUPLICATE KEY UPDATE Hits=Hits+1';
        $ustmt = $mysql->stmt_init();
        $ustmt->prepare($usql);
        $ustmt->bind_param('ii', $data['bssid'], $data['d_id']);
        $ustmt->execute();
        $ustmt->close();
        echo long2mac($data['bssid'])."-{$data['dpath']}";
    }
} else {
    echo 'No nets';
}

$stmt->close();
$mysql->close();
?>
