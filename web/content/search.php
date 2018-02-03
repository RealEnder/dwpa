<h1>Search networks</h1>
<?php
$search = $_GET['search'];
if (strlen($search) >= 3) {
    require_once('db.php');
    require_once('common.php');

    $k = '';
    if (isset($_COOKIE['key']))
        if (valid_key($_COOKIE['key']))
            $k = $_COOKIE['key'];

    // search by BSSID
    if (valid_mac($search)) {
        $bssid = mac2long($search);
        if ($k == $bosskey)
            $sql = 'SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, nets.ts
FROM nets
WHERE bssid = ?
ORDER BY net_id DESC';
        else
            $sql = 'SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, IF(n.u_id IS NULL, IF(nets.pass IS NULL,NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
FROM (SELECT * FROM nets WHERE bssid = ? ORDER BY nets.net_id DESC) AS nets
LEFT JOIN (SELECT n2u.net_id AS net_id, users.u_id AS u_id FROM n2u, users WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)) AS n ON n.net_id=nets.net_id';
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
            $sql = 'SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, nets.ts
FROM nets
WHERE bssid >> 24 = ?
ORDER BY net_id DESC';
        else
            $sql = 'SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, IF(n.u_id IS NULL, IF(nets.pass IS NULL,NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
FROM (SELECT * FROM nets WHERE bssid >> 24 = ? ORDER BY nets.net_id DESC) AS nets
LEFT JOIN (SELECT n2u.net_id AS net_id, users.u_id AS u_id FROM n2u, users WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)) AS n ON n.net_id=nets.net_id';
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
            $sql = 'SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, nets.ts
FROM nets
WHERE ssid LIKE ?
ORDER BY nets.net_id DESC';
        else
            $sql = 'SELECT hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, IF(n.u_id IS NULL, IF(nets.pass IS NULL,NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
FROM (SELECT * FROM nets WHERE ssid LIKE ? ORDER BY nets.net_id DESC LIMIT 20) AS nets
LEFT JOIN (SELECT n2u.net_id AS net_id, users.u_id AS u_id FROM n2u, users WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)) AS n ON n.net_id=nets.net_id';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        if ($k == $bosskey)
            $stmt->bind_param('s', $ssid);
        else
            $stmt->bind_param('ss', $ssid, $k);
    }
    $stmt->execute();
    
    $data = array();
    stmt_bind_assoc($stmt, $data);
    write_nets($stmt, $data);

    $stmt->close();
    $mysql->close();
} else {
    echo 'Search for at least 3 chars or BSSID';
}
?>
