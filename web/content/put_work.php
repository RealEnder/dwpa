<?php
// Parse input
try {
    $json = json_decode(file_get_contents('php://input'), True, 4, JSON_THROW_ON_ERROR);
} catch (Exception $e) {
    http_response_code(400);
    die();
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
