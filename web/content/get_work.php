<?
if (version_compare($_GET['get_work'], MIN_HC_VER) < 0 )
    die('Version');

//check and validate options
if (! array_key_exists('options', $_POST))
    die('Options');

require_once('db.php');
require_once('common.php');

//avoid race condition
$sem1 = sem_get(999);
sem_acquire($sem1);
    
//get work
$sql = 'SELECT * FROM onets, get_dict LIMIT 1';
$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$data = array();
stmt_bind_assoc($stmt, $data);
$stmt->execute();

if ($stmt->fetch()) {
    $stmt->free_result();
    //return network data

    $usql = 'INSERT INTO n2d(net_id, d_id) VALUES(?, ?) ON DUPLICATE KEY UPDATE Hits=Hits+1, ts=NOW()';
    $ustmt = $mysql->stmt_init();
    $ustmt->prepare($usql);
    $ustmt->bind_param('ii', $data['net_id'], $data['d_id']);
    $ustmt->execute();
    $ustmt->close();

    $json = array();
    $json['mic']  = strtolower($data['mic']);
    $json['bssid']  = long2mac($data['bssid']);
    $json['dpath']  = $data['dpath'];
    $json['dhash']  = strtolower($data['dhash']);
    $json['cap']  = base64_encode($data['cap']);
    $json['hccap']  = base64_encode($data['hccap']);

    echo json_encode($json);
} else {
    echo 'No nets';
}

//release critical section
sem_release($sem1);

$stmt->close();
$mysql->close();
?>
