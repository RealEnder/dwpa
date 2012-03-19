<?
require('conf.php');
require('db.php');
require('common.php');

$tmpcap = SHM.'check_db.cap';
$log = 'cdb.log';

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

echo 'Got '.count($nets)." nets from db\n";
file_put_contents($log, 'Got '.count($nets)." nets from db\n", FILE_APPEND);

foreach ($nets as $net) {
    $net_id = $net[0]; 
    $bssid  = $net[1];
    $nhash  = $net[2];

    //put decompressed cap in SHM
    file_put_contents($tmpcap, gzinflate(substr(file_get_contents(MD5CAPS.substr($nhash, 0, 3)."/$nhash.gz"), 10)));
    //check md5 hash vs nhash
    if ($nhash != md5_file($tmpcap)) {
        echo "Hash does not match! net_id: $net_id nhash:$nhash\n";
        file_put_contents($log, "Hash does not match! net_id: $net_id nhash:$nhash\n", FILE_APPEND);
    }
    $pres = '';
    exec(PYRIT.' -r '.$tmpcap.' analyze', $pres, $rc);
    if ($rc == 0) {
        $spres = implode("\n", $pres);
        if (strpos($spres, 'got 1 AP(s)') === FALSE) {
            echo "More nets found? net_id: $net_id nhash: $nhash\n";
            echo $spres."\n";
            file_put_contents($log, "More nets found? net_id: $net_id nhash: $nhash\n", FILE_APPEND);
            file_put_contents($log, $spres."\n", FILE_APPEND);
        }
    } else {
        echo "Pyrit failed: net_id:$net_id nhash:$nhash\n";
        file_put_contents($log, "Pyrit failed: net_id:$net_id nhash:$nhash\n", FILE_APPEND);
        file_put_contents($log, $spres."\n", FILE_APPEND);
    }
    if ($i % 1000 == 0) {
        echo "Net: $i\n";
        file_put_contents($log, "Net: $i\n", FILE_APPEND);
    }
    $i++;
    unlink($tmpcap);
}

echo 'Done';
file_put_contents($log, 'Done', FILE_APPEND);
?>
