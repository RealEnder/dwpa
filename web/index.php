<?
$content = 'content/';
$keys = array('home', 'submit', 'nets', 'dicts', 'stats', 'search');

list($key) = each($_GET);
if (!in_array($key,$keys))
	$key = 'home';

$cont = $content.$key.'.php';
?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>

<meta http-equiv="Content-type" content="text/html; charset=UTF-8" />
<meta name="description" content="besside-ng wpa crack" />
<meta name="keywords" content="besside-ng, wpa, crack, wordlist" />
<meta name="author" content="Alex Stanev, http://sec.stanev.org" />

<title>Free online WPA cracker with stats - besside-ng companion</title>

<link rel="stylesheet" href="style.css" type="text/css" media="screen" />

</head>
<body>

<a name="top"></a>

<div id="header">Free online WPA cracker</div>

<ul id="navtop">
<li style="float:right;"><form action="?" method="get">Search nets <input class="searchinput" type="text" id="search" name="search" value="" /></form></li>
<li><a href="?">Home</a></li>
<li><a href="?submit">Submit</a></li>
<li><a href="?nets">Nets</a></li>
<li><a href="?dicts">Dicts</a></li>
<li><a href="?stats">Stats</a></li>
</ul>
<div id="maincontainer">

<div id="contentwrapper">
<div id="contentcolumn">

<?@include($cont)?>

</div>
</div>

<div id="footer">
<div class="hr"><hr /></div>
Contact: sorbo at darkircop dot org, alex at stanev dot org
</div>

</div>
</body>
</html>
