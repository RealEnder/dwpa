<?php
require_once('db.php');
require_once('common.php');

put_work($mysql);

echo '<h1>My networks</h1>';

$limit  = 20;
$k      = (isset($_COOKIE['key']) && valid_key($_COOKIE['key'])) ? $_COOKIE['key'] : '';
$offset = (isset($_GET['page']) && is_numeric($_GET['page'])) ? ((int)$_GET['page'] -1) * $limit : 0;
$page   = ($offset / $limit) + 1;

$sql = 'SELECT SQL_CALC_FOUND_ROWS hex(nets.hash) as hash, nets.bssid AS bssid, nets.ssid AS ssid, nets.pass AS pass, nets.hits, n2u.ts
FROM nets, n2u, users
WHERE nets.net_id=n2u.net_id AND users.u_id=n2u.u_id AND users.userkey=UNHEX(?)
ORDER BY nets.net_id DESC
LIMIT ?,?';

$total_sql = 'SELECT FOUND_ROWS()';

$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$stmt->bind_param('sii', $k, $offset, $limit);
$ab = $stmt->execute();
$data = array();
stmt_bind_assoc($stmt, $data);
write_nets($stmt, $data);

$stmt->close();

$stmt = $mysql->prepare($total_sql);
$stmt->execute();
$stmt->bind_result($total);
$stmt->fetch();

$stmt->close();
$mysql->close();

for ($i=1; $i<ceil($total / $limit) + 1; ++$i) {
  if ($page == $i) {
    echo "<span class='pagging active'>$i</span>";
  } else {
    echo "<a href='?my_nets&page=$i' class='pagging'>$i</a>";
  }
}

?>
