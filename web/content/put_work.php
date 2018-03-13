<?php
require_once('conf.php');
require_once('db.php');
require_once('common.php');

if (put_work($mysql, $_POST)) {
    echo 'OK';
} else {
    echo 'Nope';
}

// mark by hkey in n2d
if (isset($_POST['hkey']) && valid_key($_POST['hkey'])) {
    $stmt = $mysql->stmt_init();
    $stmt->prepare('UPDATE n2d SET hkey=NULL WHERE hkey=UNHEX(?)');
    $stmt->bind_param('s', $_POST['hkey']);
    $stmt->execute();
    $stmt->close();
}

$mysql->close();
?>
