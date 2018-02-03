<?php
require_once('db.php');
require_once('common.php');

put_work($mysql);

echo '<h1>Last 20 submitted networks</h1>';

$k = '';
if (isset($_COOKIE['key']))
    if (valid_key($_COOKIE['key']))
        $k = $_COOKIE['key'];

if ($k == $bosskey)
    $sql = 'SELECT hex(nets.hash) AS hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, nets.ts
FROM nets
ORDER BY net_id DESC
LIMIT 20';
else
    $sql = 'SELECT hex(nets.hash) AS hash, nets.bssid AS bssid, nets.ssid AS ssid, IF(n.u_id IS NULL, IF(nets.pass IS NULL,NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
FROM (SELECT * FROM nets ORDER BY nets.net_id DESC LIMIT 20) AS nets
LEFT JOIN (SELECT n2u.net_id AS net_id, users.u_id AS u_id FROM n2u, users WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?) LIMIT 20) AS n ON n.net_id=nets.net_id';

$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
if ($k != $bosskey)
    $stmt->bind_param('s', $k);
$stmt->execute();
$data = array();
stmt_bind_assoc($stmt, $data);
write_nets($stmt, $data);

$stmt->close();
$mysql->close();
?>
