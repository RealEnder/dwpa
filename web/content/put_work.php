<?
require_once('db.php');
require_once('common.php');

if (put_work($mysql))
    echo 'OK';
else
    echo 'Nope';

$mysql->close();
?>
