<?php if (!$_FILES['webfile']): ?>
<h1>Submit WPA handshake captures</h1>
<br>
You must submit captures only from networks you have permission to capture and audit.<br>
The interface accepts libpcap native capture format and pcapng.
<script>
function check_key() {
    if (!document.getElementById('remkey'))
        return confirm("Are you sure you want to submit capture without key?\nYou will not be able to see the PSKs");
    return true;
}
</script>
<form id="submitform" class="form" method="post" action="?submit" enctype="multipart/form-data">
<input class="input" type="file" id="webfile" name="webfile">
<br><br>
<input class="submitbutton" type="submit" value="Submit capture" onclick="return check_key()">
</form>
<?php else:
    if ($_FILES['webfile']['tmp_name'] != '') {
        require_once('../db.php');
        require_once('../common.php');
        if ($res = submission($mysql, $_FILES['webfile']['tmp_name'])) { // assignment here is OK
            echo "<pre>$res</pre>";
        } else {
            echo 'Bad capture file';
        }
        $mysql->close();
    } else {
        echo 'No capture submitted';
    }
endif;
?>
