<?
//phpMailer object creation and configuration
require_once('m/class.phpmailer.php');
require_once('m/class.smtp.php');

$mailer = new PHPMailer(true);
$mailer->IsSMTP();
$mailer->IsHTML(false);
$mailer->SMTPAuth   = true;
$mailer->SMTPSecure = 'ssl';
$mailer->Host       = 'smtp.gmail.com';
$mailer->Port       = 465;
$mailer->CharSet    = 'UTF-8';
$mailer->SMTPKeepAlive = true;
$mailer->FromName   = 'wpa-sec.stanev.org';
$mailer->From       = '';
$mailer->Username   = '';
$mailer->Password   = '';
$mailer->CharSet    = 'iso-8859-1';
?>
