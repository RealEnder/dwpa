<h1>Statistics</h1>
<p>
<?
require_once('db.php');
require_once('common.php');

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
echo "Last day getworks: {$stats['24getwork']}<br/>\n";
$perf = convert_num($stats['24psk']/(60*60*24));
echo "Last day performance: $perf/s<br/>\n";
?>
</p>
