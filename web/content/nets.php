<?
require('db.php');
require('common.php');

put_work($mysql);

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
