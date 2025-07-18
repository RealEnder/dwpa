<?php
// Use this to migrate the DB to m22000 hashes
// run it from web root BEFORE updating the php files

if(php_sapi_name() !== 'cli') {
    die('Run this from cli');
}

require('conf.php');
require('db.php');
require('common.php');

$mysql->query("SET GLOBAL innodb_flush_log_at_trx_commit = 2");

//$mysql->query("DROP TABLE nets_mig");

// Create migration target table nets_mig
echo "Create table nets_mig...";
$res = $mysql->query("
CREATE TABLE nets_mig (
  net_id bigint NOT NULL AUTO_INCREMENT,
  s_id bigint NOT NULL,
  bssid bigint unsigned NOT NULL COMMENT 'AP BSSID',
  mac_sta bigint unsigned NOT NULL COMMENT 'Station mac address',
  ssid varbinary(32) NOT NULL COMMENT 'AP SSID',
  pass varbinary(64) DEFAULT NULL COMMENT 'Pre-Shared Key (PSK)',
  pmk binary(32) DEFAULT NULL COMMENT 'Pairwise Master Key (PMK)',
  algo varchar(32) CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL COMMENT 'Identified algo',
  hash binary(16) NOT NULL COMMENT 'MD5 value, based on hashline',
  struct varchar(2000) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL COMMENT 'm22000 hashline',
  message_pair tinyint unsigned DEFAULT NULL COMMENT 'message_pair value',
  keyver tinyint unsigned NOT NULL COMMENT '1-WPA 2-WPA2 3-WPA2 AES-128-CMAC 100-PMKID',
  nc smallint DEFAULT NULL COMMENT 'Nonce error correction',
  endian enum('BE','LE') CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL COMMENT 'Endianness if detected from nonce error correction',
  sip int unsigned DEFAULT NULL COMMENT 'PSK submitter IP',
  sts timestamp NULL DEFAULT NULL COMMENT 'PSK submission timestamp',
  n_state tinyint(1) NOT NULL DEFAULT '0' COMMENT '0 - not cracked, 1 - cracked, 2 - uncrackable',
  ts timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Submission timestamp',
  hits smallint unsigned NOT NULL DEFAULT '0' COMMENT 'Attempts count',
  PRIMARY KEY (net_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3
");
if ($res) echo "OK\n"; else die($res);

// Get nets row count
echo "Get nets row count...";
$res = $mysql->query("SELECT COUNT(1) FROM nets");
$netscount = $res->fetch_row()[0];
echo " $netscount records\n";

// Migrate nets data into nets_mig
$mysqlin = mysqli_init();
$mysqlin->real_connect($cfg_db_host, $cfg_db_user, $cfg_db_pass, $cfg_db_name);
if ($mysqlin->errno) {
	die("Second connection failed!\n");
}
$stmtin = $mysqlin->stmt_init();
$stmtin->prepare('INSERT INTO nets_mig VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');

$stmt = $mysql->stmt_init();
$stmt->prepare('SELECT * FROM nets ORDER BY net_id');
$data = [];
stmt_bind_assoc($stmt, $data);
$stmt->execute();

$mysqlin->query("START TRANSACTION");
$c = 0;
while ($stmt->fetch()) {
    $c++;
    $struct = convert22000($data['struct']);
    $hash = _hash_m22000($struct);

    $stmtin->bind_param('iiiissssssiiisisisi',
                        $data['net_id'],
                        $data['s_id'],
                        $data['bssid'],
                        $data['mac_sta'],
                        $data['ssid'],
                        $data['pass'],
                        $data['pmk'],
                        $data['algo'],
                        $hash,
                        $struct,
                        $data['message_pair'],
                        $data['keyver'],
                        $data['nc'],
                        $data['endian'],
                        $data['sip'],
                        $data['sts'],
                        $data['n_state'],
                        $data['ts'],
                        $data['hits']);
    $stmtin->execute();

    if ($c % 1000 == 0) echo "\rRecords $c of $netscount migrated";
}
$mysqlin->query("COMMIT");
//$mysqlin->query("SET GLOBAL innodb_flush_log_at_trx_commit = 1");
$stmtin->close();
$mysqlin->close();
$stmt->close();
echo "\n";


// Get total migrated rows and compare
echo "Compare migrated rows count...";
$res = $mysql->query("SELECT COUNT(1) FROM nets_mig");
$nets_migcount = $res->fetch_row()[0];
if ($netscount == $nets_migcount) {
    echo "OK\n";
} else {
    die("Error! nets:$netscount nets_mig: $nets_migcount records\n");
}

// Get cracked nets_mig row count
echo "Get cracked nets_mig row count...";
$res = $mysql->query("SELECT COUNT(1) FROM nets_mig WHERE n_state=1");
$ccount = $res->fetch_row()[0];
echo " $ccount records\n";

// Verify cracked after migration
$stmt = $mysql->stmt_init();
$stmt->prepare('SELECT net_id, struct, pass, pmk, nc FROM nets_mig WHERE n_state=1');
$data = [];
stmt_bind_assoc($stmt, $data);
$stmt->execute();

$c = 0;
while ($stmt->fetch()) {
    $c++;
    $res = _check_key_ng($data['struct'], [$data['pass']], $data['pmk'], abs((int) $data['nc']) * 2);
    //$res = _check_key_ng($data['struct'], [$data['pass']], Null, abs((int) $data['nc']) * 2);
    if (!$res) {
        var_dump($res);
        die('Recrack failed!');
    }

    if ($c % 1000 == 0) echo "\rRecords $c of $ccount recracked";
}
$stmt->close();
echo "\n";

// Drop references to nets
echo "Drop references to nets table";
$res = $mysql->query("ALTER TABLE n2d DROP FOREIGN KEY FK_n2d_nets_net_id");
if ($res) echo '.'; else die("FK_n2d_nets_net_id failed!\n");
$res = $mysql->query("ALTER TABLE n2u DROP FOREIGN KEY FK_n2u_nets_net_id");
if ($res) echo '.'; else die("FK_n2u_nets_net_id failed!\n");
$res = $mysql->query("ALTER TABLE rkg DROP FOREIGN KEY FK_rkg_nets_net_id");
if ($res) echo '.'; else die("FK_rkg_nets_net_id failed!\n");
$res = $mysql->query("ALTER TABLE nets DROP FOREIGN KEY FK_nets_submissions_s_id");
if ($res) echo '.'; else die("FK_nets_submissions_s_id failed!\n");
echo "OK\n";

// Drop nets trigger and indexes
echo "Drop nets trigger and indexes";
$res = $mysql->query("DROP TRIGGER IF EXISTS TRG_nets_bssids");
if ($res) echo '.'; else die("TRG_nets_bssids failed!\n");
$res = $mysql->query("DROP INDEX FK_nets_submissions ON nets");
if ($res) echo '.'; else die("FK_nets_submissions failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_bssid ON nets");
if ($res) echo '.'; else die("IDX_nets_bssid failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_n_state ON nets");
if ($res) echo '.'; else die("IDX_nets_n_state failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_mac_sta ON nets");
if ($res) echo '.'; else die("IDX_nets_mac_sta failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_ssid ON nets");
if ($res) echo '.'; else die("IDX_nets_ssid failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_algo ON nets");
if ($res) echo '.'; else die("IDX_nets_algo failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_sts ON nets");
if ($res) echo '.'; else die("IDX_nets_sts failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_ts ON nets");
if ($res) echo '.'; else die("IDX_nets_ts failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_keyver ON nets");
if ($res) echo '.'; else die("IDX_nets_keyver failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_pmk ON nets");
if ($res) echo '.'; else die("IDX_nets_pmk failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_keyver_n_state ON nets");
if ($res) echo '.'; else die("IDX_nets_keyver_n_state failed!\n");
$res = $mysql->query("DROP INDEX IDX_nets_n_state_hits_ts_algo ON nets");
if ($res) echo '.'; else die("IDX_nets_n_state_hits_ts_algo failed!\n");
echo "OK\n";

// Create foreign keys, indexes and trigger
echo "Creating FK, IDX, TRG";
$res = $mysql->query("ALTER TABLE nets_mig ADD CONSTRAINT IDX_nets_hash UNIQUE KEY (hash)");
if ($res) echo '.'; else die("IDX_nets_hash failed!\n");

$res = $mysql->query("CREATE INDEX FK_nets_submissions ON nets_mig (s_id)");
if ($res) echo '.'; else die("FK_nets_submissions failed!\n");
$res = $mysql->query("ALTER TABLE nets_mig ADD CONSTRAINT FK_nets_submissions_s_id FOREIGN KEY (s_id) REFERENCES submissions (s_id)");
if ($res) echo '.'; else die("FK_nets_submissions_s_id failed!\n");

$res = $mysql->query("ALTER TABLE n2d ADD CONSTRAINT FK_n2d_nets_net_id FOREIGN KEY (net_id) REFERENCES nets_mig (net_id)");
if ($res) echo '.'; else die("FK_n2d_nets_net_id failed!\n");
$res = $mysql->query("ALTER TABLE n2u ADD CONSTRAINT FK_n2u_nets_net_id FOREIGN KEY (net_id) REFERENCES nets_mig (net_id)");
if ($res) echo '.'; else die("FK_n2u_nets_net_id failed!\n");
$res = $mysql->query("ALTER TABLE rkg ADD CONSTRAINT FK_rkg_nets_net_id FOREIGN KEY (net_id) REFERENCES nets_mig (net_id)");
if ($res) echo '.'; else die("FK_rkg_nets_net_id failed!\n");


$res = $mysql->query("CREATE INDEX IDX_nets_bssid ON nets_mig (bssid)");
if ($res) echo '.'; else die("IDX_nets_bssid failed!\n");
$res = $mysql->query("CREATE INDEX IDX_nets_n_state ON nets_mig (n_state)");
if ($res) echo '.'; else die("IDX_nets_n_state failed!\n");
$res = $mysql->query("CREATE INDEX IDX_nets_mac_sta ON nets_mig (mac_sta)");
if ($res) echo '.'; else die("IDX_nets_mac_sta failed!\n");
$res = $mysql->query("CREATE INDEX IDX_nets_ssid ON nets_mig (ssid)");
if ($res) echo '.'; else die("IDX_nets_ssid failed!\n");
$res = $mysql->query("CREATE INDEX IDX_nets_algo ON nets_mig (algo)");
if ($res) echo '.'; else die("IDX_nets_algo failed!\n");
$res = $mysql->query("CREATE INDEX IDX_nets_sts ON nets_mig (sts)");
if ($res) echo '.'; else die("IDX_nets_sts failed!\n");
$res = $mysql->query("CREATE INDEX IDX_nets_ts ON nets_mig (ts)");
if ($res) echo '.'; else die("IDX_nets_ts failed!\n");
$res = $mysql->query("CREATE INDEX IDX_nets_keyver ON nets_mig (keyver)");
if ($res) echo '.'; else die("IDX_nets_keyver failed!\n");
$res = $mysql->query("CREATE INDEX IDX_nets_pmk ON nets_mig (pmk)");
if ($res) echo '.'; else die("IDX_nets_pmk failed!\n");
$res = $mysql->query("CREATE INDEX IDX_nets_keyver_n_state ON nets_mig (keyver, n_state)");
if ($res) echo '.'; else die("IDX_nets_keyver_n_state failed!\n");
$res = $mysql->query("CREATE INDEX IDX_nets_n_state_hits_ts_algo ON nets_mig (n_state, hits, ts, algo)");
if ($res) echo '.'; else die("IDX_nets_n_state_hits_ts_algo failed!\n");
$res = $mysql->query("CREATE TRIGGER TRG_nets_bssids AFTER INSERT ON nets_mig FOR EACH ROW BEGIN
    INSERT IGNORE INTO bssids(bssid, ts) VALUES(NEW.bssid, NEW.ts);
END");
if ($res) echo '.'; else die("TRG_nets_bssids failed!\n");

echo "OK\n";

// Rename nets to nets_oldmig and nets_mig to nets
echo "Rename nets to nets_oldmig and nets_mig to nets";
$res = $mysql->query("RENAME TABLE nets TO nets_oldmig");
if ($res) echo '.'; else die("Rename nets failed!\n");
$res = $mysql->query("RENAME TABLE nets_mig TO nets");
if ($res) echo '.'; else die("Rename nets_mig failed!\n");

echo "OK\n";

$mysql->query("SET GLOBAL innodb_flush_log_at_trx_commit = 1");

die();

function _hash_m22000($hashline) {
    $ahl = explode('*', $hashline, 9);
    if (count($ahl) != 9) return False;

    return hash('md5', $ahl[1].$ahl[2].$ahl[3].$ahl[4].$ahl[5].$ahl[6].$ahl[7], True);
}

// SIGNATURE*TYPE*PMKID/MIC*MACAP*MACSTA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
function convert22000($in) {
    if (strlen($in) == 393 && strncmp($in, 'HCPX', 4) == 0) {
        // hccapx
        $ahccapx = unpack('x8/H2message_pair/Cessid_len/H64essid/x1/H32keymic/H12mac_ap/H64nonce_ap/H12mac_sta/x32/veapol_len/H512eapol', $in);
        $ahccapx['essid'] = substr($ahccapx['essid'], 0, $ahccapx['essid_len'] * 2);
        $ahccapx['eapol'] = substr($ahccapx['eapol'], 0, $ahccapx['eapol_len'] * 2);

        return "WPA*02*{$ahccapx['keymic']}*{$ahccapx['mac_ap']}*{$ahccapx['mac_sta']}*{$ahccapx['essid']}*{$ahccapx['nonce_ap']}*{$ahccapx['eapol']}*{$ahccapx['message_pair']}";
    } else {
        // pmkid
        $pmkid = str_replace(':', '*', trim($in));
        if (substr_count($pmkid, '*') == 3) {
            return "WPA*01*$pmkid***";
        }
    }

    return False;
}

/*
hashline format:
SIGNATURE*TYPE*PMKID/MIC*MACAP*MACSTA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
3      + 1+2+ 1+   32 + 1 +12+1+12+1+ 64+  1+64  +1+ 320  +1+2

    SIGNATURE = "WPA"
    TYPE = 01 for PMKID, 02 for EAPOL, others to follow
    PMKID/MIC = PMKID if TYPE==01, MIC if TYPE==02
    MACAP = MAC of AP
    MACSTA = MAC of station
    ESSID = ESSID
    ANONCE = ANONCE
    EAPOL = EAPOL (SNONCE is in here)
    MESSAGEPAIR = Bitmask:
0: MP info (https://hashcat.net/wiki/doku.php?id=hccapx)*
1: MP info (https://hashcat.net/wiki/doku.php?id=hccapx)*
2: MP info (https://hashcat.net/wiki/doku.php?id=hccapx)*
3: x (unused)
4: ap-less attack (set to 1) - no nonce-error-corrections necessary
5: LE router detected (set to 1) - nonce-error-corrections only for LE necessary
6: BE router detected (set to 1) - nonce-error-corrections only for BE necessary
7: not replaycount checked (set to 1) - replaycount not checked, nonce-error-corrections definitely necessary
    *
000 = M1+M2, EAPOL from M2 (challenge)
001 = M1+M4, EAPOL from M4 (authorized)
010 = M2+M3, EAPOL from M2 (authorized)
011 = M2+M3, EAPOL from M3 (authorized)
100 = M3+M4, EAPOL from M3 (authorized)
101 = M3+M4, EAPOL from M4 (authorized)
    PMKID INFO = For type 01, bitmask:
0: reserved
1: PMKID taken from AP
2: reserved
4: PMKID taken from CLIENT (wlan.da: possible MESH or REPEATER)
5: reserved
6: reserved
7: reserved

Return value:
False - Not cracked
[PSK, NC, BE/LE, PMK]
*/

?>
