<h1>Dictionaries</h1>
<p>
The wordlists are compilation from different sources and are stripped from duplicates. Created with <a href="http://sec.stanev.org/?download">wlc</a> tool.
</p>
<style>
td {padding-left: 7px; padding-right: 7px}
</style>
<table style="border: 1;">
<tr><th>Dictionary</th><th>Word count</th><th>Hits</th></tr>
<?
require_once('db.php');
$sql = 'SELECT dpath, dname, wcount, hits FROM dicts ORDER BY wcount DESC';
$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$stmt->execute();
$data = array();
stmt_bind_assoc($stmt, $data);
while ($stmt->fetch())
    echo "<tr><td><a href=\"{$data['dpath']}\">{$data['dname']}</td><td align=\"right\">{$data['wcount']}</td><td align=\"right\">{$data['hits']}</td></tr>\n";
$stmt->close();
$mysql->close();
?>
</table>
