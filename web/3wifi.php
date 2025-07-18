<?php
// run this only via cli
if(php_sapi_name() !== 'cli') {
    die('Run this from cli');
}

require('conf.php');

if ($wifi3apikey == '') {
    die('3wifi API key not set!');
}

require('db.php');
require('common.php');

$wifi3search = [];

// fetch unchecked nets
$result = $mysql->query('SELECT bssid
FROM bssids
WHERE EXISTS (SELECT 1
              FROM nets
              WHERE n_state=0 AND algo IS NOT NULL AND nets.bssid=bssids.bssid)
ORDER BY wifi3ts ASC LIMIT 100');
$bssids = $result->fetch_all(MYSQLI_ASSOC);
$result->free();

// create array for 3wifi query
$wifi3search = [];
foreach ($bssids as $bssid) {
    $wifi3search[] = bin2hex($bssid['bssid']);
}

// query 3wifi
if (count($wifi3search) > 0) {
    $sub = [];
    $opts = ['http' =>
        [
            'method'  => 'POST',
            'header'  => ['Content-Type: application/json', 'User-Agent: wpa-sec'],
            'content' => json_encode(['key' => $wifi3apikey, 'bssid' => $wifi3search])
        ]
    ];
    $context = stream_context_create($opts);
    $result = file_get_contents('https://3wifi.stascorp.com/api/apiquery', FALSE, $context);
    if ($result) {
        $result = json_decode($result, TRUE);
    }
    if ($result && isset($result['result']) && $result['result'] && isset($result['data'])) {
        $i = 0;
        if (count($result['data']) > 0) {
            $stmt = $mysql->stmt_init();
            $stmt->prepare('UPDATE bssids SET flags=flags | 1 WHERE bssid=?');
            foreach ($result['data'] as $d) {
                $bssidkey = sprintf('z%03d%s', $i, $d[0]['bssid']);
                $sub[$bssidkey] = $d[0]['key'];
                $i++;
                $stmt->bind_param('s', hex2bin($d[0]['bssid']));
                $stmt->execute();
            }
            $stmt->close();
        }

        // submit founds
        if ($i > 0) {
            put_work($mysql, $sub);
        }

        // update wifi3ts
        // TODO: this is suboptimal. Try to rewrite it with one query
        $stmt = $mysql->stmt_init();
        $stmt->prepare('UPDATE bssids SET wifi3ts=CURRENT_TIMESTAMP() WHERE bssid=?');
        foreach ($bssids as $bssid) {
            $stmt->bind_param('i', $bssid['bssid']);
            $stmt->execute();
        }
        $stmt->close();
    }
}

$mysql->close();
exit(0);
?>
