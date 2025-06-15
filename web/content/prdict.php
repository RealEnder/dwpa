<?php
// Valid hex hash
function valid_hash($hash) {
    return preg_match('/^[a-f0-9]{32}$/', strtolower($hash));
}

if (!valid_hash($_GET['prdict'])) {
    die('No work package hash provided');
}

require_once('../db.php');
require_once('../common.php');

$hkey = hex2bin($_GET['prdict']);

$stmt = $mysql->stmt_init();
$stmt->prepare('SELECT DISTINCT prs.ssid
FROM prs, p2s, submissions s, nets n, n2d
WHERE prs.pr_id = p2s.pr_id
AND p2s.s_id = s.s_id
AND s.s_id = n.s_id
AND n.net_id = n2d.net_id
AND n2d.hkey = ?');
$stmt->bind_param('s', $hkey);
$stmt->execute();
$result = $stmt->get_result();
$ssids = $result->fetch_all(MYSQLI_NUM);
$result->free();
$stmt->close();

$dict = [];
foreach ($ssids as $ssid) {
    if (ctype_print($ssid[0])) {
        $dict []= $ssid[0];
    } else {
        $dict []= '$HEX[' . bin2hex($ssid[0]) . ']';
    }
}
unset($ssids);

header('Content-type: application/gzip');
header('Content-Disposition: attachment; filename=prdict.txt.gz;');
echo gzencode(implode("\n", $dict) . "\n", 4);
?>
