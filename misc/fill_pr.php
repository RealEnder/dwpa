<?php
// Use this script to fill PRS table with PROBEREQUEST frames info

// run this only via cli
if(php_sapi_name() !== 'cli') {
    die('Run this from cli');
}

require('conf.php');
require('db.php');
require('common.php');
error_reporting(E_ALL);

// fetch submissions
echo "Fetch submissions...";
$result = $mysql->query('SELECT s_id, localfile FROM submissions ORDER BY s_id');
$submissions = $result->fetch_all(MYSQLI_ASSOC);
$result->free();
$subcount = count($submissions);
echo "$subcount\n";

$stmt_pr = $mysql->stmt_init();
$stmt_pr->prepare('INSERT IGNORE INTO prs(ssid) VALUES (?)');

$stmt_p2s = $mysql->stmt_init();
$stmt_p2s->prepare('INSERT IGNORE INTO p2s(pr_id, s_id) VALUES ((SELECT pr_id FROM prs WHERE ssid=?), ?)');

$stmt_p2s_new = $mysql->stmt_init();
$stmt_p2s_new->prepare('INSERT IGNORE INTO p2s(pr_id, s_id) VALUES (?, ?)');

$prc = 0;

foreach ($submissions as $k => $sub) {
    $prfile = tempnam(SHM, '22000');
    $res = '';
    $rc  = 0;
    exec(HCXPCAPTOOL." -R $prfile {$sub['localfile']} 2>&1", $res, $rc);

    $c = 0;
    if (file_exists($prfile)) {
        $mysql->begin_transaction();

        $fp = fopen($prfile, 'r');
        while ($prline = fgets($fp)) {
            $pr = hc_unhex(rtrim($prline));
            if ($pr == '') continue;
            $c++;

            $stmt_pr->bind_param('s', $pr);
            $stmt_pr->execute();
            $pr_id = $mysql->insert_id;

            if ($pr_id == 0) {
                $stmt_p2s->bind_param('si', $pr, $sub['s_id']);
                $stmt_p2s->execute();
            } else {
                $stmt_p2s_new->bind_param('ii', $pr_id, $sub['s_id']);
                $stmt_p2s_new->execute();
            }
        }
        fclose($fp);

        $mysql->commit();


        @unlink($prfile);
    }
    $ck = $k+1;
    $prc += $c;
    echo "\r{$ck} of $subcount | Total PR: $prc | Current PR: $c     ";
}

$stmt_pr->close();
$stmt_p2s->close();
$stmt_p2s_new->close();

echo "\nDone\n";
