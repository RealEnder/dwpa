<h1>Search networks</h1>
<?php
echo '<h1>Search networks</h1>';

$search = '';
if (isset($_GET['search'])) {
    $search = $_GET['search'];
}
if (strlen($search) >= 3) {
    require_once('db.php');
    require_once('common.php');

    $k = '';
    if (isset($_COOKIE['key']) && valid_key($_COOKIE['key'])) {
        $k = $_COOKIE['key'];
    }

    // detect if we'll search for BSSID ot mac_sta
    $column = 'bssid';
    if (str_starts_with($search, 'client:')) {
        $search = trim(substr($search, 7));
        $column = 'mac_sta';
    }

    // search by BSSID or mac_sta
    if (valid_mac($search)) {
        $bssid = mac2long($search);
        if ($k == $bosskey)
            $sql = "SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.keyver AS keyver, nets.pass AS pass, nets.hits, nets.ts, nets.n_state AS n_state
FROM nets
WHERE $column = ?
ORDER BY ts DESC";
        else
            $sql = "SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.keyver AS keyver, IF(n.u_id IS NULL, IF(nets.pass IS NULL,NULL, 'Found'), nets.pass) AS pass, nets.hits, nets.ts, nets.n_state AS n_state
FROM (SELECT * FROM nets WHERE $column = ? ORDER BY nets.ts DESC LIMIT 20) AS nets
LEFT JOIN (SELECT n2u.net_id AS net_id, users.u_id AS u_id FROM n2u, users WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)) AS n ON n.net_id=nets.net_id";
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        if ($k == $bosskey)
            $stmt->bind_param('i', $bssid);
        else
            $stmt->bind_param('is', $bssid, $k);
    // search by partial BSSID
    } elseif (valid_mac($search, 3)) {
        $bssid = mac2long($search);
        if ($k == $bosskey)
            $sql = "SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.keyver AS keyver, nets.pass AS pass, nets.hits, nets.ts, nets.n_state AS n_state
FROM nets
WHERE $column >> 24 = ?
ORDER BY ts DESC";
        else
            $sql = "SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.keyver AS keyver, IF(n.u_id IS NULL, IF(nets.pass IS NULL,NULL, 'Found'), nets.pass) AS pass, nets.hits, nets.ts, nets.n_state AS n_state
FROM (SELECT * FROM nets WHERE $column >> 24 = ? ORDER BY nets.ts DESC LIMIT 20) AS nets
LEFT JOIN (SELECT n2u.net_id AS net_id, users.u_id AS u_id FROM n2u, users WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)) AS n ON n.net_id=nets.net_id";
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        if ($k == $bosskey)
            $stmt->bind_param('i', $bssid);
        else
            $stmt->bind_param('is', $bssid, $k);
    // search by SSID
    } else {
        $ssid = "$search%";
        if (strpos($search, '_') || strpos($search, '%')) {
            $ssid = $search;
        }
        if ($k == $bosskey)
            $sql = 'SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.keyver AS keyver, nets.pass AS pass, nets.hits, nets.ts, nets.n_state AS n_state
FROM nets
WHERE ssid LIKE ?
ORDER BY nets.ts DESC';
        else
            $sql = 'SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.keyver AS keyver, IF(n.u_id IS NULL, IF(nets.pass IS NULL,NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts, nets.n_state AS n_state
FROM (SELECT * FROM nets WHERE ssid LIKE ? ORDER BY nets.ts DESC LIMIT 20) AS nets
LEFT JOIN (SELECT n2u.net_id AS net_id, users.u_id AS u_id FROM n2u, users WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)) AS n ON n.net_id=nets.net_id';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        if ($k == $bosskey)
            $stmt->bind_param('s', $ssid);
        else
            $stmt->bind_param('ss', $ssid, $k);
    }

    $stmt->execute();
    $result = $stmt->get_result();
    $datas = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    $mysql->close();

    write_nets($datas);
} else {
    echo 'Search for at least 3 chars or BSSID/half BSSID';
}
?>
