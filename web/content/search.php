<h1>Search networks</h1>
<?
if (strlen($_GET['search']) >= 4) {
    require_once('db.php');
    require_once('common.php');

    $k = '';
    if (isset($_COOKIE['key']))
        if (valid_key($_COOKIE['key']))
            $k = $_COOKIE['key'];

    if (valid_mac($_GET['search'])) {
        $bssid = mac2long($_GET['search']);
        if ($k == $bosskey)
            $sql = 'SELECT hex(nets.nhash) as nhash, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, nets.ts
FROM nets
WHERE bssid = ?
ORDER BY net_id DESC';
        else
            $sql = 'SELECT hex(nets.nhash) as nhash, nets.bssid AS bssid, nets.ssid AS ssid, IF(users.u_id IS NULL, IF(nets.pass IS NULL, NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
FROM nets LEFT JOIN users ON nets.u_id=users.u_id AND users.ukey=?
WHERE bssid = ?
ORDER BY nets.net_id DESC';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        if ($k == $bosskey)
            $stmt->bind_param('i', $bssid);
        else
            $stmt->bind_param('si', $k, $bssid);
    } else {
        $ssid = "{$_GET['search']}";
        if ($k == $bosskey)
            $sql = 'SELECT hex(nets.nhash) as nhash, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, nets.ts
FROM nets
WHERE MATCH(ssid) AGAINST (?)
ORDER BY nets.net_id DESC';
        else
            $sql = 'SELECT hex(nets.nhash) as nhash, nets.bssid AS bssid, nets.ssid AS ssid, IF(users.u_id IS NULL, IF(nets.pass IS NULL, NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
FROM nets LEFT JOIN users ON nets.u_id=users.u_id AND users.ukey=?
WHERE MATCH(ssid) AGAINST (?)
ORDER BY nets.net_id DESC';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        if ($k == $bosskey)
            $stmt->bind_param('s', $ssid);
        else
            $stmt->bind_param('ss', $k, $ssid);
    }
    $stmt->execute();
    
    $data = array();
    stmt_bind_assoc($stmt, $data);
    write_nets($stmt, $data);

    $stmt->close();
    $mysql->close();
} else {
    echo 'Search for at least 4 chars or BSSID';
}
?>
