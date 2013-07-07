<?
require('conf.php');
require('db.php');
require('common.php');

$tmpcap = SHM.'check_db.cap';
$log = 'cdb.log';

function logit($mess) {
    global $log;

    echo "$mess\n";
    file_put_contents($log, "$mess\n", FILE_APPEND);
}

$sql = 'SELECT net_id, bssid, HEX(nhash) AS nhash FROM nets';
$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$stmt->execute();
$data = array();
stmt_bind_assoc($stmt, $data);

$nets = array();
$i = 0;

while ($stmt->fetch())
    $nets[] = array($data['net_id'], long2mac($data['bssid']), strtolower($data['nhash']));
$stmt->close(); 
$mysql->close();

logit('Got '.count($nets).' nets from db');

foreach ($nets as $net) {
    $net_id = $net[0]; 
    $bssid  = $net[1];
    $nhash  = $net[2];

    //put decompressed cap in SHM
    file_put_contents($tmpcap, gzinflate(substr(file_get_contents(MD5CAPS.substr($nhash, 0, 3)."/$nhash.gz"), 10)));
    //check md5 hash vs nhash
    if ($nhash != md5_file($tmpcap))
        logit("Hash does not match! net_id: $net_id nhash:$nhash");

    $pres = '';
    exec(PYRIT.' -r '.$tmpcap.' analyze', $pres, $rc);
    if ($rc == 0) {
        $spres = implode("\n", $pres);
        if (strpos($spres, 'got 1 AP(s)') === FALSE) {
            logit("More nets found? net_id: $net_id nhash: $nhash");
            logit("$spres\n");
        }
    } else {
        logit("Pyrit failed: net_id:$net_id nhash:$nhash");
        logit("$spres\n");
    }
    if ($i % 1000 == 0)
        echo "Net: $i\n";

    $i++;
    unlink($tmpcap);
}

logit('Done');
?>