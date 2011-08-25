<?
require('db.php');
require('common.php');
if (!empty($_POST)) {
    //Check stmt
    $sql = 'SELECT * FROM nets WHERE bssid = ? AND n_state=0';
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);
    $data = array();
    stmt_bind_assoc($stmt, $data);

    //Update key stmt
    $usql = 'UPDATE nets SET pass=?, sip=?, n_state=1, sts=NOW() WHERE bssid=?';
    $ustmt = $mysql->stmt_init();
    $ustmt->prepare($usql);

    $mcount = 0;
    foreach ($_POST as $bssid => $key) {
        if ($mcount++ > 20)
            break;
        if (valid_mac($bssid) && strlen($key) >= 8) {
            $ibssid = mac2long($bssid);
            $stmt->bind_param('i', $ibssid);
            $stmt->execute();

            if ($stmt->fetch())
                if (check_pass($bssid, $key)) {
                    $stmt->free_result();
                    $iip = ip2long($_SERVER['REMOTE_ADDR']);
                    $ustmt->bind_param('sii', mysqli_real_escape_string($mysql, $key), $iip, $ibssid);
                    $ustmt->execute();
                }
        }
    }
    $stmt->close();
    $ustmt->close();
}

echo '<h1>Last 20 submitted networks</h1>';
$sql = 'SELECT * FROM nets ORDER BY ts DESC LIMIT 20';
$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$stmt->execute();
$data = array();
stmt_bind_assoc($stmt, $data);
write_nets($stmt, $data);

$stmt->close();
$mysql->close();
?>
