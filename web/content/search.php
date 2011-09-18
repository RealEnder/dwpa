<h1>Search networks</h1>
<?
if (strlen($_GET['search']) >= 3) {
    require_once('db.php');
    require_once('common.php');

    $k = '';
    if (isset($_COOKIE['key']))
        if (strlen($_COOKIE['key']) == 32)
            $k = $_COOKIE['key'];

    if (valid_mac($_GET['search'])) {
        $bssid = mac2long($_GET['search']);
        $sql = 'SELECT nets.bssid AS bssid, nets.ssid AS ssid, IF(users.u_id IS NULL, IF(nets.pass IS NULL, NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
FROM nets LEFT JOIN users ON nets.u_id=users.u_id AND users.ukey=?
WHERE bssid = ?
ORDER BY nets.ts DESC';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        $stmt->bind_param('si', $k, $bssid);
    } else {
        $ssid = "%{$_GET['search']}%";
        $sql = 'SELECT nets.bssid AS bssid, nets.ssid AS ssid, IF(users.u_id IS NULL, IF(nets.pass IS NULL, NULL, \'Found\'), nets.pass) AS pass, nets.hits, nets.ts
FROM nets LEFT JOIN users ON nets.u_id=users.u_id AND users.ukey=?
WHERE ssid LIKE ?
ORDER BY nets.ts DESC';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        $stmt->bind_param('ss', $k, $ssid);
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
