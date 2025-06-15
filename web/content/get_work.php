<?php
// Valid hex hash
function valid_hash($hash) {
    return preg_match('/^[a-f0-9]{32}$/', strtolower($hash));
}

// Associate handshakes to dict
function insert_n2d(& $mysql, & $ref) {
    if (count($ref) < 2) {
        return;
    }

    $bindvars = 'iis';
    $sql = 'INSERT IGNORE INTO n2d(net_id, d_id, hkey) VALUES'.implode(',', array_fill(0, (count($ref)-1)/strlen($bindvars), '('.implode(',',array_fill(0, strlen($bindvars), '?')).')'));
    $stmt = $mysql->stmt_init();
    $stmt->prepare($sql);

    $ref[0] = str_repeat($bindvars, (count($ref)-1)/strlen($bindvars));
    call_user_func_array([$stmt, 'bind_param'], $ref);
    $stmt->execute();
    $stmt->close();
}

// Check incoming version string
if (version_compare($_GET['get_work'], MIN_HC_VER) < 0 ) {
    die('Version');
}

// Check PoW
if (apcu_exists("wpasecpow{$_SERVER['REMOTE_ADDR']}")) {
    http_response_code(412);
    die('Wait');
}

// Parse input
try {
    $json = json_decode(file_get_contents('php://input'), True, 2, JSON_THROW_ON_ERROR);
} catch (Exception $e) {
    http_response_code(400);
    die();
}

require_once('../db.php');
require_once('../common.php');

// check desired dict count
$dictcount = 1;
if (array_key_exists('dictcount', $json)) {
    $dictcount = filter_var($json['dictcount'],
                            FILTER_VALIDATE_INT,
                            ['options' => ['default' => 1, 'min_range' => 1, 'max_range' => 15]]);
}

// critical section begin
create_lock('get_work.lock');
$mysql->begin_transaction();

// generate get_work key
$hkey = gen_key();
$bhkey = hex2bin($hkey);

// get current dict
$stmt = $mysql->stmt_init();
$stmt->prepare("SELECT d_id, HEX(dhash) as dhash, dpath, rules, rnd_words
FROM dicts d
WHERE NOT EXISTS (SELECT d_id
              FROM n2d
              WHERE d.d_id=n2d.d_id AND
                    n2d.net_id=(SELECT net_id
                                FROM nets
                                WHERE n_state=0 AND
                                      algo=''
                                ORDER BY hits, ts
                                LIMIT 1))
ORDER BY d.wcount, d.dname
LIMIT ?");
$stmt->bind_param('i', $dictcount);
$stmt->execute();
$result = $stmt->get_result();
$dicts = $result->fetch_all(MYSQLI_ASSOC);
$result->free();
$dc = count($dicts);

if ($dc == 0) {
    release_lock('get_work.lock');
    $mysql->close();
    die('No nets');
}

// add hkey, dicts and rules
$resnet = ['hkey' => $hkey, 'dicts' => [], 'hashes' => []];
$ref = [''];
$rules = [];
$rnd_words = [];
for ($i=0; $i<$dc; $i++) {
    $resnet['dicts'][] = ['dhash' => strtolower($dicts[$i]['dhash']), 'dpath' => $dicts[$i]['dpath']];
    $ref[] = & $dicts[$i]['d_id'];
    $rules = array_unique(array_merge($rules, explode("\n", $dicts[$i]['rules'])));
    // Don't use all random words for now, so we'll not cripple the performance if we've got crack
    // $rnd_words = array_merge($rnd_words, explode("\n", $dicts[$i]['rnd_words']));
}
$resnet['rules'] = base64_encode(implode("\n", $rules));
// take random words from the first dict. See above.
$rnd_words = explode("\n", $dicts[0]['rnd_words']);

// get nets and prepare
$stmt = $mysql->stmt_init();
$stmt->prepare("SELECT net_id, struct
FROM nets n
WHERE ssid = BINARY (SELECT ssid
                 FROM nets
                 WHERE n_state=0 AND
                       algo=''
                 ORDER BY hits, ts
                 LIMIT 1) AND
  n_state=0 AND
  algo='' AND
  net_id NOT IN (SELECT net_id
                 FROM n2d
                 WHERE d_id IN (".implode(',', array_fill(0, $dc, '?')).") AND
                       n2d.net_id = n.net_id)
LIMIT 20");
$ref[0] = str_repeat('i', $dc);
call_user_func_array([$stmt, 'bind_param'], $ref);
$stmt->execute();
$result = $stmt->get_result();
$nets = $result->fetch_all(MYSQLI_ASSOC);
$result->free();

if (count($nets) == 0) {
    release_lock('get_work.lock');
    $mysql->close();
    die('No nets');
}

$ref = [''];
foreach ($nets as $key => $net) {
    $resnet['hashes'][] = $net['struct'];

    for ($i = 0; $i < $dc; $i++) {
        $ref[] = & $nets[$key]['net_id'];
        $ref[] = & $dicts[$i]['d_id'];
        $ref[] = & $bhkey;
    }
}

// populate in n2d
insert_n2d($mysql, $ref);

// increment hits for selected nets
$stmt = $mysql->stmt_init();
$stmt->prepare("UPDATE nets
JOIN (
    SELECT net_id, COUNT(1) AS cnt
    FROM n2d
    WHERE hkey = ?
    GROUP BY net_id
    ) AS x USING (net_id)
SET nets.hits = nets.hits + x.cnt");
$stmt->bind_param('s', $bhkey);
$stmt->execute();

// critical section end
$mysql->commit();
release_lock('get_work.lock');

// increment hits for selected dicts
$stmt = $mysql->stmt_init();
$stmt->prepare("UPDATE dicts
JOIN (
    SELECT d_id, COUNT(1) AS cnt
    FROM n2d
    WHERE hkey = ?
    GROUP BY d_id
    ) AS x USING (d_id)
SET dicts.hits = dicts.hits + x.cnt");
$stmt->bind_param('s', $bhkey);
$stmt->execute();

/* Add PoW hash */
// compute PoW PMK
$pow_arr = explode('*', $resnet['hashes'][0]);
$pow_pass = $rnd_words[array_rand($rnd_words)];
$pmk = openssl_pbkdf2($pow_pass, hex2bin($pow_arr[5]), 32, 4096, 'sha1');
// generate random BSSID and mac_sta. Don't care for unicast/multicast for now
$pow_mac_ap  = random_bytes(6);
$pow_mac_sta = random_bytes(6);
// compute PoW PMK
$pow_pmkid   = hash_hmac('sha1', 'PMK Name' . $pow_mac_ap . $pow_mac_sta, $pmk, False);
$pow_hash = sprintf('WPA*01*%s*%s*%s*%s***01', substr($pow_pmkid, 0, 32), bin2hex($pow_mac_ap), bin2hex($pow_mac_sta), $pow_arr[5]);

// add PoW PMKID and shuffle the array
$resnet['hashes'][] = $pow_hash;
shuffle($resnet['hashes']);

// cache PoW with 1h TTL
apcu_store("wpasecpow{$_SERVER['REMOTE_ADDR']}", $pow_pass, 3600);

// add PRdict if availible
$stmt = $mysql->stmt_init();
$stmt->prepare('SELECT 1
FROM prs, p2s, submissions s, nets n, n2d
WHERE prs.pr_id = p2s.pr_id
AND p2s.s_id = s.s_id
AND s.s_id = n.s_id
AND n.net_id = n2d.net_id
AND n2d.hkey = ?
LIMIT 1');
$stmt->bind_param('s', $bhkey);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows == 1) {
    $resnet['prdict'] = True;
}

echo json_encode($resnet);
?>
