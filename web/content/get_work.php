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

// Parse input
try {
    $json = json_decode(file_get_contents('php://input'), True, 2, JSON_THROW_ON_ERROR);
} catch (Exception $e) {
    http_response_code(400);
    die();
}

require_once('db.php');
require_once('common.php');

// check desired dict count
$dictcount = 1;
if (array_key_exists('dictcount', $json)) {
    $dictcount = filter_var($json['dictcount'],
                            FILTER_VALIDATE_INT,
                            ['default' => 1, 'min_range' => 1, 'max_range' => 15]);
}

// critical section begin
create_lock('get_work.lock');

// generate get_work key
$hkey = gen_key();
$bhkey = hex2bin($hkey);

// API key validation and user job prioritization
$api_key = isset($json['api_key']) ? trim($json['api_key']) : '';
$user_clause = '';

if ($api_key !== '') {
    // Validate API key format
    if (!valid_key($api_key)) {
        error_log("Invalid API key format received from " . $_SERVER['REMOTE_ADDR']);
        http_response_code(400);
        die('Invalid API key');
    }

    try {
        // Try to find user's uncracked submissions first
        $stmt = $mysql->stmt_init();
        $query = "SELECT net_id 
                 FROM nets n 
                 JOIN n2u ON n.net_id = n2u.net_id 
                 JOIN users ON n2u.u_id = users.u_id 
                 WHERE users.userkey = UNHEX(?)
                 AND n.n_state = 0 
                 AND n.algo = ''
                 ORDER BY n.hits, n.ts 
                 LIMIT 1";
                 
        if (!$stmt->prepare($query)) {
            throw new Exception("Failed to prepare user jobs query");
        }
        
        $stmt->bind_param('s', $api_key);
        
        if (!$stmt->execute()) {
            throw new Exception("Failed to execute user jobs query"); 
        }
        
        $stmt->store_result();
        
        // If user has uncracked submissions, prioritize those
        if ($stmt->num_rows > 0) {
            $user_clause = " AND net_id IN (
                SELECT net_id 
                FROM n2u 
                JOIN users ON n2u.u_id = users.u_id 
                WHERE users.userkey = UNHEX('$api_key')
            )";
        }
        
        $stmt->close();
    }
    catch (Exception $e) {
        error_log("Database error in API key check: " . $e->getMessage());
        release_lock('get_work.lock');
        http_response_code(500);
        die('Database error');
    }
}

// get current dict
$stmt = $mysql->stmt_init();
$stmt->prepare("SELECT d_id, HEX(dhash) as dhash, dpath, rules
FROM dicts d
WHERE NOT EXISTS (SELECT d_id
              FROM n2d
              WHERE d.d_id=n2d.d_id AND
                    n2d.net_id=(SELECT net_id
                                FROM nets
                                WHERE n_state=0 AND
                                      algo=''
                                      $user_clause
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
for ($i=0; $i<$dc; $i++) {
    $resnet['dicts'][] = ['dhash' => strtolower($dicts[$i]['dhash']), 'dpath' => $dicts[$i]['dpath']];
    $ref[] = & $dicts[$i]['d_id'];
    $rules = array_unique(array_merge($rules, explode("\n", $dicts[$i]['rules'])));
}
$resnet['rules'] = base64_encode(implode("\n", $rules));

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
                       n2d.net_id = n.net_id)");
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

// critical section end
release_lock('get_work.lock');

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
