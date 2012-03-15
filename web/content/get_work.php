<?
if (version_compare($_GET['get_work'], MIN_HC_VER) < 0 ) {
    echo 'Version';
    exit(0);
}

require_once('db.php');
require_once('common.php');

//avoid race condition
//add critical section for now
//TODO: fix this in mysql
$sem = sem_get(999);
sem_acquire($sem);
    
//get work
$sql = 'SELECT * FROM onets, get_dict LIMIT 1';
$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$data = array();
stmt_bind_assoc($stmt, $data);
$stmt->execute();

if ($stmt->fetch()) {
    $stmt->free_result();
    //return capture md5 hash+dict
    $usql = 'INSERT INTO n2d(net_id, d_id) VALUES(?, ?) ON DUPLICATE KEY UPDATE Hits=Hits+1, ts=NOW()';
    $ustmt = $mysql->stmt_init();
    $ustmt->prepare($usql);
    $ustmt->bind_param('ii', $data['net_id'], $data['d_id']);
    $ustmt->execute();
    $ustmt->close();
    echo strtolower($data['nhash']).'\\'.long2mac($data['bssid']).'\\'.$data['dpath'];
} else {
    echo 'No nets';
}

//release critical section
sem_release($sem);
sem_remove($sem);

$stmt->close();
$mysql->close();
?>
