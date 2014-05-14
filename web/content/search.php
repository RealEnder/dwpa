<h1>Search networks</h1>
<?
if (strlen($_GET['search']) >= 3) {
    require_once('db.php');
    require_once('common.php');

    $k = '';
    if (isset($_COOKIE['key']))
        if (valid_key($_COOKIE['key']))
            $k = $_COOKIE['key'];

    if (valid_mac($_GET['search'])) {
        $bssid = mac2long($_GET['search']);
        if ($k == $bosskey)
            $sql = 'SELECT hex(nets.mic) as mic, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, nets.ts
FROM nets
WHERE bssid = ?
ORDER BY net_id DESC';
        else
            $sql = 'SELECT hex(nets.mic) as mic, nets.bssid AS bssid, nets.ssid AS ssid, IF(n.u_id IS NULL, IF(nets.pass IS NULL,NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
FROM (SELECT * FROM nets WHERE bssid = ? ORDER BY nets.net_id DESC) AS nets
LEFT JOIN (SELECT n2u.net_id AS net_id, users.u_id AS u_id FROM n2u, users WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)) AS n ON n.net_id=nets.net_id';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        if ($k == $bosskey)
            $stmt->bind_param('i', $bssid);
        else
            $stmt->bind_param('is', $bssid, $k);
    } else {
        $ssid = "%{$_GET['search']}%";
        if ($k == $bosskey)
            $sql = 'SELECT hex(nets.mic) as mic, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, nets.ts
FROM nets
WHERE ssid LIKE ?
ORDER BY nets.net_id DESC';
        else
            $sql = 'SELECT hex(nets.mic) as mic, nets.bssid AS bssid, nets.ssid AS ssid, IF(n.u_id IS NULL, IF(nets.pass IS NULL,NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
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
