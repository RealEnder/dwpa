<?php
// wpa-sec DB maintenance script - does stats, dict regen and etc. nice stuff

// run this only via cli
if(php_sapi_name() !== 'cli') {
    die('Run this from cli');
}

require('conf.php');
require('db.php');
require('common.php');

// rebuild stats
// TODO: replace this with SELECT n_state, keyver, count(distinct bssid), count(net_id), count(distinct ssid) FROM nets USE INDEX (IDX_nets_keyver_n_state) group by n_state, keyver; + CASE multiple update
echo "Calculate stats\n";
$mysql->query("UPDATE stats SET pvalue = (SELECT count(1) FROM nets WHERE n_state<2) WHERE pname='nets'");
$mysql->query("UPDATE stats SET pvalue = (SELECT count(1) FROM bssids) WHERE pname='nets_unc'");
$mysql->query("UPDATE stats SET pvalue = (SELECT count(1) FROM nets WHERE n_state=1) WHERE pname='cracked'");
$mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1) WHERE pname='cracked_unc'");

$mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE keyver=100 AND n_state<2) WHERE pname='pmkid'");
$mysql->query("UPDATE stats SET pvalue = (SELECT count(net_id) FROM nets WHERE n_state=1 AND keyver=100) WHERE pname='cracked_pmkid'");
$mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE keyver=100 AND n_state<2) WHERE pname='pmkid_unc'");
$mysql->query("UPDATE stats SET pvalue = (SELECT count(DISTINCT bssid) FROM nets WHERE n_state=1 AND keyver=100) WHERE pname='cracked_pmkid_unc'");

$mysql->query("UPDATE stats SET pvalue=(SELECT count(distinct net_id) FROM n2d WHERE ts >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY)) WHERE pname='24getwork'");
$mysql->query("UPDATE stats SET pvalue=(SELECT sum(wcount) FROM n2d, dicts WHERE ts >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY) AND n2d.d_id=dicts.d_id) WHERE pname='24psk'");
$mysql->query("UPDATE stats SET pvalue=(SELECT count(1) FROM nets WHERE sts >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY) AND n_state=1) WHERE pname='24founds'");
$mysql->query("UPDATE stats SET pvalue=(SELECT count(1) FROM nets WHERE ts >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY) AND n_state<2) WHERE pname='24sub'");
$mysql->query("UPDATE stats SET pvalue=(SELECT nc*wc FROM (SELECT SUM(wcount) AS wc FROM dicts) d, (SELECT COUNT(1) AS nc FROM nets WHERE n_state=0) n) WHERE pname='words'");
$mysql->query("UPDATE stats SET pvalue=(SELECT SUM(dicts.wcount) FROM n2d, dicts WHERE dicts.d_id = n2d.d_id) WHERE pname='triedwords'");
$mysql->query("UPDATE stats SET pvalue=(SELECT count(1) FROM bssids WHERE lat IS NOT NULL) WHERE pname='wigle_found'");

// cleanup n2d leftovers
echo "Cleanup n2d leftovers\n";
$mysql->query("DELETE FROM n2d WHERE hkey IS NOT NULL AND TIMESTAMPDIFF(HOUR, ts, CURRENT_TIMESTAMP) > 3");
$mysql->query("DELETE FROM n2d WHERE EXISTS (SELECT 1 FROM nets WHERE nets.net_id = n2d.net_id AND nets.n_state != 0)");

//rebuild cracked dict
echo "Pull cracked.txt.gz dict\n";
$stmt = $mysql->stmt_init();
$stmt->prepare("SELECT pass
FROM (SELECT DISTINCT ssid, pass
    FROM nets
    WHERE n_state=1 AND (algo IS NULL OR algo = '')
     ) t
GROUP BY pass
ORDER BY count(pass) DESC");
$stmt->execute();
$stmt->bind_result($key);

echo "Write cracked.txt.gz dict\n";
// write compressed wordlist
$wpakeys = tempnam(CAP, 'wpakeys');
chmod($wpakeys, 0644);
$fd = gzopen($wpakeys, 'wb9');
while ($stmt->fetch()) {
    if (!ctype_print($key)) {
        $key = '$HEX[' . bin2hex($key) . ']';
    }
    gzwrite($fd, "$key\n");
}
$keycount = $stmt->num_rows;
$stmt->close();
gzclose($fd);

$md5 = hash_file('md5', $wpakeys, True);
rename($wpakeys, CRACKED);

// update wcount for cracked dict
echo "Update cracked.txt.gz word count\n";
$cr = '%'.basename(CRACKED);
$sql = 'UPDATE dicts SET wcount = ?, dhash = ? WHERE dpath LIKE ?';
$stmt = $mysql->stmt_init();
$stmt->prepare($sql);
$stmt->bind_param('iss', $keycount, $md5, $cr);
$stmt->execute();
$stmt->close();

echo "Done\n";
?>
