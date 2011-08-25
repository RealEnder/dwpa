<? if (!$_FILES['file']): ?>
<h1>Submit WPA handshake captures</h1>
<script type="text/javascript">
function check_file() {
    str=document.getElementById('file').value.toUpperCase();
    suffix=".CAP";
    if(!(str.indexOf(suffix, str.length - suffix.length) !== -1)){
        alert('File type not allowed\nAllowed file: *.cap');
        document.getElementById('file').value='';
    }
}
</script>
<form id="submitform" class="form" method="post" action="?submit" enctype="multipart/form-data">
<p>
<input class="input" type="file" id="file" name="file" onchange="check_file()"/>
</p>
<p>
<input class="submitbutton" type="submit" value="Submit capture" />
</p>
</form>
<? else:
    $file = $_FILES['file']['tmp_name'];
    $filtercap = $file.'filter';

    // Clean and merge WPA captures
    require('common.php');
    $res = '';
    $rc = 0;
    exec(WPACLEAN." $filtercap ".WPA_CAP." $file", $res, $rc);
    if ($rc == 0) {
        // Check if we have any new networks
        require('db.php');
        $sql = 'INSERT IGNORE INTO nets(bssid, ssid, ip) VALUES(?, ?, ?)';
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);

        $newcap = false;
        foreach ($res as $net) {
            if (!$newcap)
                if (strpos($net, $file) !== false) {
                    $newcap = true;
                    continue;
                } else
                    continue;
            if (strlen($net) > 22) {
                //check in db
                $mac = mac2long(substr($net, 4, 17));
                $nname = mysqli_real_escape_string($mysql, substr($net, 22));
                $ip = ip2long($_SERVER['REMOTE_ADDR']);
                $stmt->bind_param('isi', $mac, $nname, $ip );
                $stmt->execute();
            }
        }
        $stmt->close();
        rename($filtercap, WPA_CAP);
        rename($file, CAP.$_SERVER['REMOTE_ADDR'].'-'.md5_file($file).'.cap');

        echo '<h1>Last 20 submitted networks from you</h1>';
        $sql = 'SELECT * FROM nets WHERE ip=? ORDER BY ts DESC LIMIT 20';
        $ip = ip2long($_SERVER['REMOTE_ADDR']);
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        $stmt->bind_param('i', $ip);
        $stmt->execute();
        $data = array();
        stmt_bind_assoc($stmt, $data);
        write_nets($stmt, $data);
        $stmt->close();
        $mysql->close();
    } else {
        echo 'Bad capture file';
        unlink($filtercap);
    }
endif;
?>
