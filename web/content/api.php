<?php
$k  = (isset($_COOKIE['key']) && valid_key($_COOKIE['key'])) ? $_COOKIE['key'] : '';
$dl = (isset($_GET['dl']) && is_numeric($_GET['dl'])) ? (int)$_GET['dl'] : 0;

header('Content-type: application/octet-stream');
header('Content-Disposition: attachment; filename="wpa-sec.founds.potfile"');

// download founds
if ($k != '' && $dl == 1) {
    require_once('../db.php');
    require_once('../common.php');

    $stmt = $mysql->stmt_init();
    $stmt->prepare('SELECT nets.bssid AS bssid, nets.mac_sta AS mac_sta, nets.ssid AS ssid, nets.pass AS pass
FROM nets, n2u, users
WHERE nets.net_id=n2u.net_id AND nets.n_state=1 AND users.u_id=n2u.u_id AND users.userkey=UNHEX(?)
ORDER BY nets.ts');
    $stmt->bind_param('s', $k);
    $stmt->execute();
    stmt_bind_assoc($stmt, $data);

    while ($stmt->fetch()) {
        printf("%s:%s:%s:%s\n", bin2hex($data['bssid']), bin2hex($data['mac_sta']), $data['ssid'], $data['pass']);
    }

    $stmt->close();
    $mysql->close();
}
?>
