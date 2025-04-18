<?php
require_once('../db.php');
require_once('../common.php');

// Check if we've got user password submissions
if ($arr = build_cand($_POST)) {
    put_work($mysql, $arr);
}

echo '<h1>Last 20 submitted networks</h1>';

$k = '';
if (isset($_COOKIE['key']) && valid_key($_COOKIE['key'])) {
    $k = $_COOKIE['key'];
}

if ($k == $bosskey) {
    $result = $mysql->query('SELECT hex(nets.hash) AS hash, nets.bssid, nets.ssid, nets.keyver, nets.message_pair, nets.pass, nets.algo, nets.nc, nets.endian, nets.hits, nets.ts, nets.n_state, bssids.country
FROM nets
LEFT JOIN bssids ON nets.bssid = bssids.bssid
WHERE n_state<2
ORDER BY ts DESC
LIMIT 20');
    $datas = $result->fetch_all(MYSQLI_ASSOC);
} else {
    if ($k == '') {
        $result = $mysql->query('SELECT hex(hash) AS hash, nets.bssid, ssid, keyver, message_pair, IF(pass IS NULL, NULL, \'Found\') AS pass, algo, nc, endian, hits, nets.ts, n_state, country
FROM nets
LEFT JOIN bssids ON nets.bssid = bssids.bssid
WHERE n_state<2
ORDER BY ts DESC
LIMIT 20');
        $datas = $result->fetch_all(MYSQLI_ASSOC);
    } else {
        $stmt = $mysql->stmt_init();
        $stmt->prepare('SELECT HEX(hash) AS hash, bssid, ssid, keyver, message_pair, IF(n.u_id IS NULL, IF(pass IS NULL, NULL, \'Found\'), pass) AS pass, algo, nc, endian, hits, ts, n_state, country
FROM (SELECT nets.*, country
      FROM nets
      LEFT JOIN bssids ON nets.bssid = bssids.bssid
      WHERE n_state<2
      ORDER BY nets.ts DESC
      LIMIT 20) AS n1
LEFT JOIN (SELECT n2u.net_id, users.u_id
           FROM n2u, users
           WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)
           LIMIT 20) AS n
ON n.net_id=n1.net_id');
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
