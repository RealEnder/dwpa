<h1>Search networks</h1>
<?
if (strlen($_GET['search']) >= 3) {
    require('db.php');
    require('common.php');
    
    if (valid_mac($_GET['search'])) {
        $bssid = mac2long($_GET['search']);
        $sql = 'SELECT * FROM nets WHERE bssid = ?';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        $stmt->bind_param('i', $bssid);
    } else {
        $ssid = "%{$_GET['search']}%";
        $sql = 'SELECT * FROM nets WHERE ssid LIKE ? ORDER BY ts';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        $stmt->bind_param('s', $ssid);
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
