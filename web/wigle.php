<?php
// run this only via cli
if(php_sapi_name() !== 'cli') {
    die('Run this from cli');
}

require('conf.php');

if ($wigleapikey == '') {
    die('wigle API key not set!');
}

require('db.php');
require('common.php');

// fetch unchecked nets
$result = $mysql->query('SELECT * FROM bssids WHERE lat IS NULL ORDER BY wiglets ASC, ts ASC LIMIT 5');
$bssids = $result->fetch_all(MYSQLI_ASSOC);
$result->free();

foreach ($bssids as $bssid) {
    $wiglesearch = long2mac($bssid['bssid']);
    $wiglesearch = implode(':', str_split($wiglesearch, 2));
    $opts = ['http' =>
        [
            'method'  => 'GET',
            'header'  => ['Content-Type: application/json', 'User-Agent: wpa-sec', 'Authorization: Basic '.$wigleapikey ]
        ]
    ];
    $context = stream_context_create($opts);
    $result = file_get_contents('https://api.wigle.net/api/v2/network/search?netid='.$wiglesearch, FALSE, $context);
    if ($result) {
        $result = json_decode($result, TRUE);
    }
    if ($result && isset($result['success']) && $result['success'] && isset($result['results'])) {
        if ($result['resultCount'] == 1) {
            $stmt = $mysql->stmt_init();
            $stmt->prepare('UPDATE bssids SET flags=flags | 2, wiglets=CURRENT_TIMESTAMP(), lat=?, lon=?, country=?, region=?, city=? WHERE bssid=?');
            $stmt->bind_param('ddsssi', $result['results'][0]['trilat'], $result['results'][0]['trilong'], $result['results'][0]['country'], $result['results'][0]['region'], $result['results'][0]['city'], $bssid['bssid']);
            $stmt->execute();
            $stmt->close();
        } else {
            // update wiglets
            $stmt = $mysql->stmt_init();
            $stmt->prepare('UPDATE bssids SET wiglets=CURRENT_TIMESTAMP() WHERE bssid=?');
            $stmt->bind_param('i', $bssid['bssid']);
            $stmt->execute();
            $stmt->close();
        }
    }

    // throttle wigle API query
    sleep(1);
}

$mysql->close();
exit(0);
?>
