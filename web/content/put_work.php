<?php
// Parse input
try {
    $json = json_decode(file_get_contents('php://input'), True, 4, JSON_THROW_ON_ERROR);
} catch (Exception $e) {
    http_response_code(400);
    die();
}

// Check for PoW
if (array_key_exists('cand', $json) && is_array($json['cand'])) {
    $success = False;
    $pow_pass = apcu_fetch("wpasecpow{$_SERVER['REMOTE_ADDR']}", $success);
    if ($success) {
        $pow_pass_count = 0;
        $pow_position = Null;

        foreach ($json['cand'] as $k=>$c) {
            if (array_key_exists('v', $c) && $pow_pass == hex2bin($c['v'])) {
                $pow_pass_count++;
                $pow_position = $k;
                if ($pow_pass_count > 1) break;
            }
        }

        if ($pow_pass_count == 1) {
            unset($json['cand'][$pow_position]);
            apcu_delete("wpasecpow{$_SERVER['REMOTE_ADDR']}");
        } else {
            unset($json['hkey']);
        }
    }
}

require_once('../conf.php');
require_once('../db.php');
require_once('../common.php');

if (put_work($mysql, $json)) {
    echo 'OK';
} else {
    echo 'Nope';
}

// mark by hkey in n2d
if (isset($json['hkey']) && valid_key($json['hkey'])) {
    $stmt = $mysql->stmt_init();
    $stmt->prepare('UPDATE n2d SET hkey=NULL WHERE hkey=UNHEX(?)');
    $stmt->bind_param('s', $json['hkey']);
    $stmt->execute();
    $stmt->close();
}

$mysql->close();
?>
