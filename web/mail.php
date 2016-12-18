<?php
//phpMailer object creation and configuration
require_once('m/class.phpmailer.php');
require_once('m/class.smtp.php');

$mailer = new PHPMailer(true);
$mailer->IsSMTP();
$mailer->IsHTML(false);
$mailer->SMTPAuth   = true;
$mailer->SMTPSecure = 'tls';
$mailer->Host       = 'smtp.gmail.com';
$mailer->Port       = 587;
$mailer->SMTPKeepAlive = true;
$mailer->FromName   = '';
$mailer->From       = '';
$mailer->Username   = '';
$mailer->Password   = '';
$mailer->CharSet    = 'utf-8';
?>
