<?php
// Use this to update PMKIDs with additional source field
// run it from web root AFTER updating the php files and DB

if(php_sapi_name() !== 'cli') {
    die('Run this from cli');
}

require('conf.php');
require('db.php');
require('common.php');
error_reporting(E_ALL);

// fetch all submissions
echo "Fetch submissions\n";
$result = $mysql->query('SELECT s_id, localfile, ts FROM submissions ORDER BY s_id');
$submissions = $result->fetch_all(MYSQLI_ASSOC);
$result->free();
$s_count = count($submissions);
$c = 0;

// prepare PMKID nets pull
$stmt = $mysql->stmt_init();
$stmt->prepare('SELECT net_id, struct FROM nets WHERE keyver=100 AND s_id=?');

// prepare PMKID update
$stmtu = $mysql->stmt_init();
$stmtu->prepare('UPDATE nets SET struct=?, message_pair=? WHERE net_id=?');

foreach ($submissions as $s) {
    $c++;
    echo "\r$c/$s_count";
    // check if we have PMKIDs with this submission    
    $stmt->bind_param('i', $s['s_id']);
    $stmt->execute();
    $result = $stmt->get_result();
    $nets = $result->fetch_all(MYSQLI_ASSOC);
    $result->free();
    if (count($nets) > 0) {
        // extract PMKIDs from the capture
        @unlink('/tmp/enrich.22000');
        $rc = 0;
        $res = '';
        exec(HCXPCAPTOOL." --nonce-error-corrections=8 --eapoltimeout=20000 --max-essids=1 -o /tmp/enrich.22000 {$s['localfile']} 2>&1", $res, $rc);
        if (file_exists('/tmp/enrich.22000')) {
            $parsed = file('/tmp/enrich.22000');
            $parsed = array_map('trim', $parsed);

            // clean parsed hashes from handshakes
            for ($i=0; $i<count($parsed); $i++) {
                if (str_starts_with($parsed[$i], 'WPA*02*')) unset($parsed[$i]);
            }

            foreach ($nets as $net) {
                foreach ($parsed as $p) {
                    if ($p == $net['struct']) continue 2;
                    if (str_starts_with($p, $net['struct'])) {
                        // we matched hash and will update
                        $arr = explode('*', $p);
                        if (count($arr) == 9) {
                            $message_pair = hexdec($arr[8]);
                            $stmtu->bind_param('sii', $p, $message_pair, $net['net_id']);
                            $stmtu->execute();
                            continue 2;
                        }
                    }
                }
            }
        }
    }
}
?>
