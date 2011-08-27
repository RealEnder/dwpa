<h1>Cracker statistics</h1>
<?
require('db.php');

$stats = array();
$sql = 'SELECT * FROM stats';
$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$data = array();
stmt_bind_assoc($stmt, $data);
$stmt->execute();

while ($stmt->fetch())
    $stats[$data['pname']] = $data['pvalue'];
$stmt->close();
$mysql->close();

echo "Total nets: {$stats['nets']}<br/>\n";
echo "Cracked nets: {$stats['cracked']}<br/>\n";
if ((int) $stats['nets'] > 0) {
    $srate = round((int) $stats['cracked'] / (int) $stats['nets'] * 100, 2);
    echo "Success rate: $srate %<br/>\n";
}
?>
