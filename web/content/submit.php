<?php if (!$_FILES['webfile']): ?>
<h1>Submit WPA handshake captures</h1>
<p>
You must submit captures only from networks you have permission to audit.<br/>
The interface accepts libpcap native capture format.
</p>
<script type="text/javascript">
function check_file() {
    str=document.getElementById('webfile').value.toUpperCase();
    suffix=".CAP";
    if(!(str.indexOf(suffix, str.length - suffix.length) !== -1)){
        alert('File type not allowed\nAllowed extension: cap');
        document.getElementById('webfile').value='';
    }
}

function check_key() {
    if (!document.getElementById('remkey'))
        return confirm("Are you sure you want to submit capture without key?\nYou will not be able to see the PSKs");
    return true;
}

</script>
<form id="submitform" class="form" method="post" action="?submit" enctype="multipart/form-data">
<p>
<input class="input" type="file" id="webfile" name="webfile" onchange="check_file()"/>
</p>
<p>
<input class="submitbutton" type="submit" value="Submit capture" onclick="return check_key()" />
</p>
</form>
<?php else:
    if ($_FILES['webfile']['tmp_name'] != '') {
        require_once('../db.php');
        require_once('../common.php');
        if ($res = submission($mysql, $_FILES['webfile']['tmp_name']))
            echo "<pre>$res</pre>";
        else
            echo 'Bad capture file';
        $mysql->close();
    } else {
        echo 'No capture submitted';
    }
endif;
?>
