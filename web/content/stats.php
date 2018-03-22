<h1>Statistics</h1>
<p>
<?php
require_once('db.php');
require_once('common.php');

$result = $mysql->query('SELECT * FROM stats');
$datas = $result->fetch_all(MYSQLI_ASSOC);
$result->free();

$stats = array();
foreach ($datas as $data) {
    $stats[$data['pname']] = $data['pvalue'];
}
// this is for all handshake stats
echo "Total handshakes: {$stats['nets']} / {$stats['nets_unc']} unique BSSIDs<br/>\n";
echo "Cracked handshakes: {$stats['cracked']} / {$stats['cracked_unc']} unique BSSIDs<br/>\n";
if ((int) $stats['nets'] > 0) {
    $srate = round((int) $stats['cracked'] / (int) $stats['nets'] * 100, 2);
    $srate_unc = round((int) $stats['cracked_unc'] / (int) $stats['nets_unc'] * 100, 2);
    echo "Success rate: $srate% / $srate_unc% unique BSSIDs<br/>\n";
}
echo '<br/>';

// this is for rkg stats
echo "Cracked by known algorithm: {$stats['cracked_rkg']} / {$stats['cracked_rkg_unc']} unique BSSIDs<br/>\n";
if ((int) $stats['cracked'] > 0) {
    $srate = round((int) $stats['cracked_rkg'] / (int) $stats['cracked'] * 100, 2);
    $srate_unc = round((int) $stats['cracked_rkg_unc'] / (int) $stats['cracked_unc'] * 100, 2);
    echo "Known algorithm success rate: $srate% / $srate_unc% unique BSSIDs<br/>\n";
}
echo '<br/>';

// last day stats
echo "Last 24h getworks: {$stats['24getwork']}<br/>\n";
$perf = convert_num($stats['24psk']/(60*60*24));
echo "Last 24h performance: $perf/s<br/>\n";
echo "Last 24h submissions: {$stats['24sub']}<br/>\n";
echo "Last 24h founds: {$stats['24founds']}<br/>\n";
echo '<br/>';

// current contributers
$result = $mysql->query('SELECT COUNT(DISTINCT hkey) AS dhkeyc, COUNT(hkey) AS hkeyc FROM n2d WHERE hkey IS NOT NULL');
$datas = $result->fetch_all(MYSQLI_ASSOC);
$result->free();

echo "Current contributors count: {$datas[0]['dhkeyc']} working on {$datas[0]['hkeyc']} handshakes\n<br/>\n";

// estimation and simple gaugage
echo "Current round ends in: ";
if ((int) $stats['24psk'] > 0)
    echo convert_sec(round(((int) $stats['words'] - (int) $stats['triedwords']) / ((int) $stats['24psk']/(60*60*24))));
else
    echo 'infinity';
echo "<br/>\n";
if ($stats['words'] == 0)
    $stats['words'] = 1;
?>
<br/>
Current keyspace progress:
<dl class="progress">
    <dd class="done" style="width: <?php echo round((int) $stats['triedwords'] / (int) $stats['words'] * 100); ?>%"><?php echo round((int) $stats['triedwords'] / (int) $stats['words'] * 100, 2); ?>%</dd>
</dl>
</p>
