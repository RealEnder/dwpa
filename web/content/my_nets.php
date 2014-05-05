<?
require_once('db.php');
require_once('common.php');

put_work($mysql);

echo '<h1>My networks</h1>';

$k = '';
if (isset($_COOKIE['key']))
    if (valid_key($_COOKIE['key']))
        $k = $_COOKIE['key'];

$sql = 'SELECT hex(nets.mic) as mic, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, n2u.ts
FROM nets, n2u, users
WHERE nets.net_id=n2u.net_id AND users.u_id=n2u.u_id AND users.userkey=UNHEX(?)
ORDER BY nets.net_id DESC
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
