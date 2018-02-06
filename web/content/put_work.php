<?php
require_once('conf.php');
require_once('db.php');
require_once('common.php');

if (put_work($mysql, $_POST)) {
    echo 'OK';
} else {
    echo 'Nope';
}

$mysql->close();
?>
