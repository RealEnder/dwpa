<?php

import_request_variables("pg", "p_");

$_fstatus = 0;
global $_stats, $_current, $_dicts, $_clients;

$_dicts = array("cow", "openwall", "insidepro", "os");
$_clients = array();

function connect_db()
{
	global $_db;

	$_db = mysql_connect("127.0.0.1", "root", "w00t");
	if (!$_db)
		die("mysql_connect()");

	if (!mysql_select_db("wpa"))
		die("mysql_select_db()");
}

function check_upload()
{
	global $p_fs, $_fstatus;

	if (!isset($p_fs))
		return;

	$_fstatus = 1;

	$file = $_FILES["file"];

	if ($file["error"] != UPLOAD_ERR_OK)
		return;

	$d = opendir("cap");
	if (!$d)
		return;

	$max = 0;

	while (($f = readdir($d)) !== FALSE) {
		if (!strstr($f, ".cap"))
			continue;

		$f = substr($f, 0, strlen($f) - 4);
		$f = (int) $f;

		if ($f > $max)
			$max = $f;
	}

	closedir($d);

	$max++;

	$dst = "cap/$max.cap";

	if (!move_uploaded_file($_FILES["file"]["tmp_name"], $dst))
		return;

	$rc  = 0;
	$out = null;
	$ip  =  $_SERVER['REMOTE_ADDR'];
	exec("cap/merge.sh $max.cap $ip", $out, $rc);

	if ($rc != 0)
		return;

	$_fstatus = 2;
}

function check_pass($bssid, $pass)
{
	$wl = "/tmp/wl";
	$kf = "/tmp/key";

	if (strlen($pass) == 0)
		return 0;

	$f = fopen($wl, 'w') or die("fopen()");
	fwrite($f, $pass . "\n");
	fclose($f);

	unlink($kf);

	$x = "aircrack-ng -b $bssid -w $wl -l $kf cap/wpa.cap";
	exec($x, $out);
	$f = fopen($kf, "r");
	if (!$f)
		return 0;

	$p = fread($f, filesize($kf));

	fclose($kf);

	return strcmp($p, $pass) == 0;
}

function save_network($k)
{
	$bssid = substr($k, 8);

	$wc      = "wpacracker-" . $bssid;
	$pass    = "pass-" . $bssid;
	$comment = $_POST["comment-" . $bssid];

	if (strlen($comment) > 0) {
		$comment = ", comments = \""
			   . mysql_real_escape_string($comment) . "\"";
	} else
		$comment = "";

	$bssid = str_replace("-", ":", $bssid);

	$wpacracker = $_POST[$wc];

	if (!isset($wpacracker))
		$wpacracker = "";
	else if ($wpacracker === "Yes")
		$wpacracker = ", wpacracker = 1";
	else if ($wpacracker === "No")
		$wpacracker = ", wpacracker = 2";
	else
		$wpacracker = ", wpacracker = 0";

	$out = "";
	if (array_key_exists($pass, $_POST)) {
		$pass = $_POST[$pass];

		if ($pass != "") {
			if (check_pass($bssid, $pass)) {
				$out = ", pass = \"" 
				       . mysql_real_escape_string($pass) . "\""
					. ", cow = 0, state = 2";
			} else {
				echo "<p>";
				echo "Bad pass";
				echo "</p>";
				return false;
			}
		}
	}	

	$q = "UPDATE nets SET rainbow = rainbow $wpacracker"
		. $comment
		. $out
		. "  WHERE bssid = \""
		. mysql_real_escape_string($bssid) . "\"";

	if (!mysql_query($q)) {
		die("mysql_query()");
	}

	return true;
}

function check_save()
{
	global $p_save;

	if (!isset($p_save))
		return;
	foreach ($_POST as $k => $v) {

		if (strncmp($k, "comment-", 8) != 0)
			continue;

		if (!save_network($k))
			return;
	}

	echo "Info saved";
}

function do_grep($fname, $stuff)
{
	$stuff = "^$stuff$";

	$x = "grep " . escapeshellarg($stuff) . " $fname";

	$out = null;
	$rc  = null;

	exec($x, $out, $rc);

	if ($rc == 0)
		return 1;

	return 2;
}

function create_current()
{
	global $_current;

	if (!isset($_current)) {
		$_current = array();
		$_current["ssid"] = "";
		$_current["tocrack"] = 0;
		$_current["cracking"] = 0;
		$_current["needcrack"] = 0;
	}
}

function check_data()
{
	global $_current;

	$r = mysql_query("SELECT * from nets order by id desc");
	if (!$r)
		die("mysql_query()");

	while ($row = mysql_fetch_assoc($r)) {
		$rain  = (int) $row["rainbow"];
		$bssid = $row["bssid"];
		$pass  = $row["pass"];

		if (strlen($pass) == 0) {
			if ($row["state"] == 1) {
				create_current();

				if (strlen($_current["ssid"]) > 0)
					$_current["ssid"] .= ", ";

				$_current["ssid"] .= $row["ssid"];
				$_current["cracking"] += 1;
			} else if($row["cow"] == 0) {
				create_current();
				$_current["tocrack"] += 1;
			}

			if (!already_cracked($row)) {
				create_current();
				$_current["needcrack"] += 1;
			}
		}

		if ($rain == 0) {
			$rain = do_grep("cow_ssid.txt", $row["ssid"]);

			$q = "UPDATE nets SET rainbow = " . $rain
                             . " WHERE bssid =\"$bssid\"";

			if (!mysql_query($q))
				die("bad");
		}

		if ($row["cow"] != 0)
			continue;

		if ($pass == "" && $row["state"] != 2)
			continue;

		$count = array();

		global $_dicts;

		foreach ($_dicts as &$d)
			$count[$d] = do_grep("wl/" . $d . ".txt", $pass);

		$first = true;
		$q = "UPDATE nets SET ";

		foreach ($_dicts as &$d) {
			$c = $count[$d];

			if ($first)
				$first = false;
			else
				$q .= ", ";

			$q .= "$d = $c";	
		}

		$q  .= " WHERE bssid = \"$bssid\"";

		if (!mysql_query($q))
			die("bad");
	}
}

function get_stats()
{
	global $_stats;

	$s = array("cow", "openwall", "insidepro", "wpacracker");

	$_stats = array();
	$_stats["total"]	= 0;
	$_stats["all"]		= 0;
	$_stats["cracked"]	= 0;
	$_stats["rainbow"]	= 0;

	foreach ($s as $x)
		$_stats[$x] = 0;

	$r = mysql_query("SELECT * from nets order by id desc");
	if (!$r)
		die("mysql_query()");

	while ($row = mysql_fetch_assoc($r)) {
		$cow = $row["cow"];
		$ow  = $row["openwall"];

		if ($cow > 0)
			$_stats["total"] += 1;

		foreach ($s as $x) {
			$val = $row[$x];

			if ($val == 1)
				$_stats[$x] += 1;
		}

		$cr = false;
		global $_dicts;

		foreach ($_dicts as $d) {
			if ($row[$d] == 1) {
				$cr = true;
				break;
			}
		}

		if ($cr)
			$_stats["cracked"] += 1;

		if ($cow == 1 && $row["rainbow"] == 1)
			$_stats["rainbow"] += 1;

		$_stats["all"] += 1;
	}
}

function already_cracked($r)
{
	if (strlen($r["pass"]) > 0)
		return true;

	$cracked = true;
	global $_dicts;
	foreach ($_dicts as $d) {
		if ($r[$d] == 0)
			$cracked = false;
	}

	if ($cracked && $r["state"] == 2)
		return true;

	return false;
}

function op_result()
{
	global $p_result, $p_pass, $p_wl, $p_bssid, $_dicts;

	if ($p_result != "")
		return;

	$trusted = false;

	if ($p_pass == "w00t")
		$trusted = true;

	$sha = file_get_contents("wl/darkircop.txt.sha1");

	if (strncmp($sha, $p_wl, strlen($sha) - 1) != 0)
		die("ERROR: bad wl");

	$q = "SELECT * from nets where bssid = \"" 
		. mysql_real_escape_string($p_bssid) . '"';

	$r = mysql_query($q);
	if (!$r)
		die("ERROR: Bad bssid");

	$r = mysql_fetch_assoc($r);
	if (!$r)
		die("ERROR: bad bssid");

	$bssid = $r["bssid"];

	if (already_cracked($r))
		die("Already cracked");

	$state = 3;
	if ($trusted)
		$state = 2;

	$q = "UPDATE nets SET state = $state";

	foreach ($_dicts as &$d)
		$q .= ", $d = 2";

	$q  .= " WHERE bssid = \"$bssid\"";

	if (!mysql_query($q))
		die("Can't update");

	echo "status: OK";
}

function op_new()
{
	global $p_speed, $p_pass;

	$ip = $_SERVER["REMOTE_ADDR"];

	$p_speed = (int) $p_speed;

	$trusted = "FALSE";
	if ($p_pass == "w00t")
		$trusted = "TRUE";

	$x = rand();

	$q = "INSERT INTO clients set id = '$x', ip = '$ip', last = NOW()"
		. ", speed = $p_speed, trusted = $trusted";

	if (!mysql_query($q))
		die("Can't update");

	echo $x;
}

function op_delete()
{
	global $p_id;

	$q = "DELETE from clients where id = \""
		. mysql_real_escape_string($p_id). "\"";

	if (!mysql_query($q))
		die("bla");

	echo "status: OK";
}

function op_ping()
{
	global $p_id;

	$q = "UPDATE clients set last = NOW() where id = \""
		. mysql_real_escape_string($p_id) . "\"";

	if (!mysql_query($q))
		die("Can't update");

	if (mysql_affected_rows() == 1)
		echo "status: OK";
	else
		die("Can't update");
}

function op_crack()
{
	global $p_bssid;

	$q = "SELECT * from nets where bssid = \""
		. mysql_real_escape_string($p_bssid) . "\"";

	$r = mysql_query($q);
	if (!$r)
		die("death");

	$r = mysql_fetch_assoc($r);
	if (!$r)
		die("death");

	if (already_cracked($r))
		die("Already cracked");

	$q = "UPDATE nets set state = 1 where bssid = \""
		. $r["bssid"] . "\"";

	if (!mysql_query($q))
		die("can't update");

	echo "status: OK";
}

function check_op()
{
	global $p_op;

	if (!isset($p_op))
		return;

	if ($p_op == "result")
		op_result();
	else if ($p_op == "crack")
		op_crack();
	else if ($p_op == "new")
		op_new();
	else if ($p_op == "ping")
		op_ping();
	else if ($p_op == "delete")
		op_delete();

	die();
}

function get_num($x)
{
	$r = mysql_query($x);
	if (!$r)
		die("get_num");

	$r = mysql_fetch_assoc($r);
	if (!$r)
		die("get_num");

	$r = $r["num"];

	return (int) $r;
}

function check_clients()
{
	global $_clients;

	$q = "DELETE from clients where (UNIX_TIMESTAMP(NOW())"
		. " - UNIX_TIMESTAMP(last)) > 700";

	if (!mysql_query($q))
		die("cc");

	$_clients["total"] = get_num("select COUNT(speed) as num from clients");

	$_clients["speed_trust"] = 
		get_num("select SUM(speed) as num from clients"
			. " where trusted = TRUE");

	$_clients["speed"] = get_num("select SUM(speed) as num from clients");

	$_clients["max"] = get_num("select MAX(speed) as num from clients"
			. "  where trusted = TRUE");
}

check_upload();

connect_db();
check_clients();
check_op();
check_data();
get_stats();

function print_stat($s)
{
	global $_stats;

	$x = (double) $_stats[$s] / (double) $_stats["total"] * 100.0;
	$x = (int) $x;

	echo "$x%";
}

global $p_fs;
if (isset($p_fs) && $_SERVER['HTTP_USER_AGENT'] == "besside-ng") {
	echo $_fstatus;
	exit;
}

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
   "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<title>Free online WPA cracker with stats - besside-ng companion</title>

<style type="text/css">

input[type="text"] {
	width: 8em;
}

th {
	text-align: left;
}

table {
	font-size: small;
}

.untrusted {
	background: #ff6666;
}

</style>

</head>
<body>

<div id="container">

<h1>Online WPA cracker with stats - besside-ng companion</h1>

<div id="status"><?php
	if ($_fstatus) {
		echo "<p>";
		if ($_fstatus == 1)
			echo "Upload FAILED";
		else
			echo "Upload successful";

		echo "</p>";
	}

	check_save();
?>
</div>

<div id="u">
<p>Upload your WPA handshake here and your network will be
cracked for you automatically.

<?php

// (current total wait time less than

// exec("wc -l wl/darkircop.txt | awk '{print $1}'", $out, $rc);
// $_dict = (int) $out[0];
$_dict = 46105640;
$speed = $_clients["speed_trust"];
if ($speed <= 0)
	$speed = 1;

$wt = 0;
$serial = 1;
if (isset($_current)) {
	$wt += $_current["tocrack"];

	if ($_current["cracking"] > 0)
		$serial++;
}

$wt = (double) $wt * (double) $_dict / (double) $speed;
$wt += (double) $serial * (double) $_dict / (double) $_clients["max"];
$wt = $wt / 60.0 / 60.0;
$x = (int) $wt;
if ($wt > $x)
	$x++;

$wt = $x;

//echo "$wt hour";

if ($wt > 1) {
//	echo "s";
}
//).
?>

Contribute to WPA security research - the more handshakes you upload, the more
stats, and the more we'll understand how feasible WPA cracking is in practice
(currently <?php print_stat("cracked"); ?> are crackable based on <?php echo
$_stats["total"]; ?> networks).
</p>

<form method="post" action="<? echo $_SERVER['PHP_SELF']; ?>" name="up"
      enctype="multipart/form-data">

<fieldset>
<legend>
Upload WPA handshake capture
</legend>
<input type="file" name="file" />

<input type="submit" name="fs" value="Upload" />
</fieldset>
</form>

<p>To obtain the WPA handshake, use besside-ng (from
<a href="http://www.aircrack-ng.org/downloads.html">aircrack-ng</a>'s SVN), a
tool that will automatically own all the WPA networks it finds.  If you have
Internet connectivity while running besside-ng, use the -s wpa.darkircop.org
option to upload wpa.cap automatically.</p>

</div>

<div id="intro">
<h2>WPA cracking in practice (live stats)</h2>
Based on <?php echo $_stats["total"]; ?> networks and a 

<?php

	$x = (double) $_dict / 1000000.0;
	$x = (int) $x;
	echo $x

?>M

word <a href="wl/darkircop.txt.gz">dictionary</a>:
<ul>
<li><b>What's the success rate when cracking WPA?  <?php print_stat("cracked");
?> (<?php echo $_stats["cracked"] ?>/<?php echo $_stats["total"] ?>).</b>
<br />WPA cracking works by trying words from a dictionary until the password
is found.  So the question is equivalent to "how many people use dictionary
words - like hello, world - as their WPA password?"</li>

<li><b>Is a large dictionary necessary?  You'll crack
<?php 
        $x = 100.0 - (double) $_stats["cow"] / (double) $_stats["cracked"] * 100.0;
	$x = (int) $x;

	echo $x;
?>% more networks from the crackable ones.</b><br/>
A large dictionary has more chances of containing the network's password.  But,
it may be that people either choose very simple passwords (so a small
dictionary will suffice) or a very complicated password (practically
uncrackable) giving large dictionaries diminishing returns.
</li>

<li><b>Do rainbow tables help?  <?php 

	$x = (double) $_stats["rainbow"] / (double) $_stats["cracked"] * 100.0;
	$x = (int) $x;

	echo $x;
?>% of the crackable networks will be cracked faster.</b> <br />Rainbow tables
speed up WPA cracking, but only when cracking networks who's name is present in
a predefined list of 1000 SSIDs.  And, the passphrase still needs to be in the
dictionary.</li>
</ul>
</div>

<h2>Real-time WPA cracking results</h2>
<?php

if (isset($_current) && 0) {

	echo "<p>";
	echo "Currently cracking <b>" . htmlspecialchars($_current["ssid"])
	     . "</b>";

	$rem = $_current["tocrack"];
	if ($rem > 0)
		echo " (and $rem more to go after that)";

	echo "</p>";
}

?>

<form name="data" method="post"
	action="<? echo $_SERVER['PHP_SELF']; ?>">
<table>
<tr>
<th>Num</th>
<th></th>
<th>SSID</th>
<th>Passphrase</th>
<th><a href="cow_ssid.txt">Rainbow</a></th>
<th><a href="wl/cow.txt.gz">CoW (1M)</a></th>
<th><a href="wl/openwall.txt.gz">Openwall (3M)</a></th>
<th><a href="wl/insidepro.txt.gz">Insidepro (11M)</a></th>
<th><a href="wl/os.txt.gz">Offensive security (39M)</a></th>
<th>Comments</th>
</tr>

<?php

$off = 0;
$limit = 100;

if (isset($p_off))
	$off = (int) $p_off;

if ($off < 0)
	$off = 0;

if (isset($p_limit))
	$limit = (int) $p_limit;

$l = $off;

if ($limit >= 0)
	$l .= ", $limit";
else {
	$l .= ", " . $_stats['all'];
	$limit = 100;
}

$r = mysql_query("SELECT * from nets order by id desc limit $l");
if (!$r)
	die("mysql_db_query()");

$num = $_stats['all'] - $off;

while ($row = mysql_fetch_assoc($r)) {
	$bssid = $row['bssid'];

	$ip = $row['ip'];
	$cc = $row['countrycode'];
	$country = $row['country'];

	if ($cc == null && ip != null) {
	        $q = "SELECT * from ipdb where inet_aton('$ip') >= start "
                	. " and inet_aton('$ip') <= end";

        	$x = mysql_fetch_assoc(mysql_query($q));
        	if ($x) {
                	$cc = $x["code"];
                	$country = $x["country"];

        		$q = "UPDATE nets set country = \"$country\""
				. ", countrycode = \"$cc\" where bssid = \"$bssid\"";

			if (!mysql_query($q))
				die("mysql_query()");
		}
	}

	$cr = $row["state"] == 1;

	$bssid = str_replace(":", "-", $bssid);

	$cl = "";
	if ($row["state"] == 3)
		$cl = ' class="untrusted"';

	echo "<tr$cl>";

	$id = $row['id'];

	echo "<td>$num";


	echo "</td>";
	$num--;

	echo "<td>";
        if ($cc != null) {
                $f = "flags/" . strtolower($cc) . ".png";


		$country = ucwords(strtolower($country));

                if (file_exists($f)) {
                        echo "<img src=\"$f\" alt=\"$country\" title=\"$country\" />";
                }
        } else
		echo "??";
	echo "</td>";

//	echo "<td>" . $row['bssid'] . "</td>";

	echo "<td>";
	if ($cr)
		echo "<b>";
	echo htmlspecialchars($row['ssid']);
	if ($cr)
		echo "</b>";
	echo "</td>";

	echo "<td>"; 
	$pass = $row['pass'];
	if ($pass == "") {
		echo "<input type=\"text\" name=\"pass-$bssid\" />";
	} else
		echo htmlspecialchars($pass);
	echo "</td>";

	echo "<td>" . print_yesno($row["rainbow"]). "</td>";

	global $_dicts;
	foreach ($_dicts as $d)
		echo "<td>" . print_yesno($row[$d]). "</td>";


	echo "<td><textarea name=\"comment-$bssid\">";
	echo htmlspecialchars($row['comments']);
	echo "</textarea></td>";

	echo "</tr>\n";
}

function is_selected($i, $x)
{
	if ($i == $x)
		return 'selected="yes"';
}

function print_yesno($i)
{
	if ($i == 1)
		return "yes";

	if ($i == 2)
		return "no";
}

?>

</table>

<input type="submit" name="save" value="Save" />
</form>

<?php

$pages = $_stats['all'] / $limit + 1;
for ($i = 1; $i <= $pages; $i++) {
	$o = ($i - 1) * $limit;
	$link = $_SERVER['PHP_SELF'] . "?off=$o";
	if ((int) ($off / $limit + 1) == $i)
		echo "$i ";
	else
		echo "<a href=\"$link\">$i</a> ";
}

$link = $_SERVER['PHP_SELF'] . "?off=0&limit=-1";
echo "<a href=\"$link\">All</a>";

?>

<p>Red, if present, means that the cracking result was uploaded by a random
dude from the Internet so we can't necessarily trust the result.  Bold means
that the network is currently being cracked.</p>

<p>
Download handshakes: <a href="cap/wpa.cap.gz">wpa.cap.gz</a>
</p>

<p>
Contribute your CPU to the cracking process by running <a
href="help_crack.sh">help_crack.sh</a> (v8), a script that will automatically
fetch uncracked networks, try to crack them, and upload the results to
this site.  If you want to use your own wordlist, pass it as an argument.
<?php /*
Currently <?php echo $_clients["total"] ?> people are donating their CPUs and
we can test <?php echo $_clients["speed"] ?> words/sec<?php

if ($_clients["speed_trust"] != $_clients["speed"] && 0)
	echo " (or " . $_clients["speed"] . " w/s if nobody is lying)";

?>.


<?php

if (isset($_current) && 0) {
	$speed = $_clients["speed_trust"];
	if ($speed <= 0)
		$speed = 1;

	$x = (double) $_current["needcrack"] 
		* (double) $_dict / (double) $speed / 60.0 / 60.0;

	$x = (int) $x;

	echo "We got a backlog of " . $_current["needcrack"] . " networks";
	echo " ($x hours).";
}

?>
*/ ?>
</p>

</div>

<p>
Contact: <a href="mailto:sorbo@darkircop.org">sorbo@darkircop.org</a>
</p> 

</body>
</html>
