<?php
require_once('db.php');
require_once('common.php');

put_work($mysql, $_POST);

echo '<h1>Last 20 submitted networks</h1>';

$k = '';
if (isset($_COOKIE['key']) && valid_key($_COOKIE['key'])) {
    $k = $_COOKIE['key'];
}

if ($k == $bosskey) {
    $result = $mysql->query('SELECT hex(nets.hash) AS hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.keyver AS keyver, nets.pass AS pass, nets.hits, nets.ts, nets.n_state AS n_state
FROM nets
ORDER BY net_id DESC
LIMIT 20');
    $datas = $result->fetch_all(MYSQLI_ASSOC);
} else {
    if ($k == '') {
        $result = $mysql->query('SELECT hex(nets.hash) AS hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.keyver AS keyver, IF(nets.pass IS NULL,NULL, \'Found\') AS pass, nets.hits, nets.ts, nets.n_state AS n_state
FROM nets
ORDER BY net_id DESC
LIMIT 20');
        $datas = $result->fetch_all(MYSQLI_ASSOC);
    } else {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT hex(nets.hash) AS hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.keyver AS keyver, IF(n.u_id IS NULL, IF(nets.pass IS NULL,NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts, nets.n_state AS n_state
FROM (SELECT * FROM nets ORDER BY nets.net_id DESC LIMIT 20) AS nets
LEFT JOIN (SELECT n2u.net_id AS net_id, users.u_id AS u_id FROM n2u, users WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?) LIMIT 20) AS n ON n.net_id=nets.net_id');
        $stmt->bind_param('s', $k);
        $stmt->execute();
        $result = $stmt->get_result();
        $datas = $result->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
    }
}
$result->free();
$mysql->close();

write_nets($datas);
?>
