<?
require_once('db.php');
require_once('common.php');

put_work($mysql);

echo '<h1>My networks</h1>';

$k = '';
if (isset($_COOKIE['key']))
    if (strlen($_COOKIE['key']) == 32)
        $k = $_COOKIE['key'];

$sql = 'SELECT hex(nets.nhash) as nhash, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, nets.ts
FROM nets, users
WHERE nets.u_id=users.u_id AND users.ukey=?
ORDER BY nets.ts DESC
LIMIT 20';

$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$stmt->bind_param('s', $k);
$stmt->execute();
$data = array();
stmt_bind_assoc($stmt, $data);
write_nets($stmt, $data);

$stmt->close();
$mysql->close();
?>
