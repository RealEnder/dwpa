<h1>Dictionaries</h1>
<br>
The wordlists are compilation from different sources and are stripped from duplicates. Created with <a href="https://sec.stanev.org/?download">wlc</a> tool.
<br>
<table class="dicts">
<tr><th>Dictionary</th><th>Word count</th><th>Hits</th></tr>
<?php
require_once('../db.php');
$result = $mysql->query('SELECT dpath, dname, wcount, hits FROM dicts ORDER BY wcount DESC, dname DESC');
$datas = $result->fetch_all(MYSQLI_ASSOC);
$result->free();
$mysql->close();

foreach ($datas as $data) {
    echo "<tr><td><a href=\"{$data['dpath']}\">{$data['dname']}</a></td><td>{$data['wcount']}</td><td>{$data['hits']}</td></tr>\n";
}
echo "</table>\n";
echo "<br>\nKeygen generated dict: <a href=\"dict/rkg.txt.gz\">rkg.txt.gz</a>\n";
?>
