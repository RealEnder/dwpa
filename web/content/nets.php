<?
require_once('db.php');
require_once('common.php');

put_work($mysql);

echo '<h1>Last 20 submitted networks</h1>';

$k = '';
if (isset($_COOKIE['key']))
    if (strlen($_COOKIE['key']) == 32)
        $k = $_COOKIE['key'];

if ($k == $bosskey)
    $sql = 'SELECT hex(nets.nhash) as nhash, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, nets.ts
FROM nets
ORDER BY net_id DESC
LIMIT 20';
else
    $sql = 'SELECT hex(nets.nhash) as nhash, nets.bssid AS bssid, nets.ssid AS ssid, IF(users.u_id IS NULL, IF(nets.pass IS NULL, NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
FROM nets LEFT JOIN users ON nets.u_id=users.u_id AND users.ukey=?
ORDER BY nets.net_id DESC
LIMIT 20';

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
