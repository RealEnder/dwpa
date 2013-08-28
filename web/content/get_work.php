<?
if (version_compare($_GET['get_work'], MIN_HC_VER) < 0 )
    die('Version');

//check and validate options
if (! array_key_exists('options', $_POST))
    die('Options');
$options = json_decode($_POST['options'], True);
if (! array_key_exists('format', $options) || ! in_array($options['format'], array('cap', 'hccap')) )
    die('Bad json/format');


require_once('db.php');
require_once('common.php');

//avoid race condition
//add critical section for now
//TODO: fix this in mysql
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
    $json['nhash']  = strtolower($data['nhash']);
    $json['bssid']  = long2mac($data['bssid']);
    $json['dpath']  = $data['dpath'];
    $json['dhash']  = strtolower($data['dhash']);
    $json['format'] = $options['format'];
    if ($options['format'] == 'cap')
        $json['net'] = base64_encode(file_get_contents(MD5CAPS.substr($json['nhash'], 0, 3)."/{$json['nhash']}.gz"));
    else
        $json['net'] = base64_encode(file_get_contents(MD5CAPS.substr($json['nhash'], 0, 3)."/{$json['nhash']}.hccap.gz"));

    echo json_encode($json);
} else {
    echo 'No nets';
}

//release critical section
sem_release($sem1);
sem_remove($sem1);

$stmt->close();
$mysql->close();
?>
