<h1>Dictionaries</h1>
<table style="border: 1;">
<tr><th>Dictionary</th><th>Word count</th><th>Hits</th></tr>
<?
require('db.php');
$sql = 'SELECT * FROM dicts ORDER BY wcount DESC';
$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$stmt->execute();
$data = array();
stmt_bind_assoc($stmt, $data);
while ($stmt->fetch())
    echo "<tr><td><a href=\"{$data['dpath']}\">{$data['dname']}</td><td>{$data['wcount']}</td><td>{$data['hits']}</td></tr>\n";
$stmt->close();
$mysql->close();
?>
</table>
