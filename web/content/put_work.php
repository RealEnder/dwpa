<?
require('db.php');
require('common.php');

if (put_work($mysql))
    echo 'OK';
else
    echo 'Nope';

$mysql->close();
?>
