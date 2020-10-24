<?php
// use this to migrate the DB structure when upgrading from pre Oct 2020 DB
// run it from web root

if(php_sapi_name() !== 'cli') {
    die('Run this from cli');
}

require('conf.php');
require('db.php');
require('common.php');

$upgrade_bssids = False;
$upgrade_nets = False;

// disable some checks
$mysql->query('SET autocommit=0');
$mysql->query('SET unique_checks=0');
$mysql->query('SET foreign_key_checks=0');

// Check current migration state
// bssids table
$res = $mysql->query('DESCRIBE bssids');
if (!$res) die("Table bssids not found!\n");

$col = $res->fetch_all(MYSQLI_ASSOC);
foreach ($col as $c) {
    if ($c['Field'] == 'bssid' && $c['Type'] == 'bigint unsigned') {
        echo "Will upgrade bssids table\n";
        $upgrade_bssids = True;
        break;
    }
}

// nets table
$res = $mysql->query('DESCRIBE nets');
if (!$res) die("Table nets not found!\n");

$col = $res->fetch_all(MYSQLI_ASSOC);
foreach ($col as $c) {
    if ($c['Field'] == 'struct') {
        echo "Will upgrade nets table\n";
        $upgrade_nets = True;
        break;
    }
}

// work on bssids table
if ($upgrade_bssids) {
    // drop indexes
    echo "Drop bssids indexes\n";
    $mysql->query('DROP INDEX IDX_bssids_flags ON bssids');
    $mysql->query('DROP INDEX IDX_bssids_ts ON bssids');
    $mysql->query('DROP INDEX IDX_bssids_lat ON bssids');
    $mysql->query('DROP INDEX IDX_bssids_lon ON bssids');
    $mysql->query('DROP INDEX IDX_bssids_wifi3ts ON bssids');

    // cleanup migration leftovers
    echo "Drop column bssid1\n";
    $res = $mysql->query('ALTER TABLE bssids DROP COLUMN bssid1');

    // add columns
    echo "Add column bssid1\n";
    $res = $mysql->query("ALTER TABLE bssids ADD COLUMN bssid1 binary(6) COMMENT 'BSSID of the network' AFTER bssid");

    // fetch the bssids, which are also PK in our case
    echo "Updating bssid1 from bssid\n";
    $res = $mysql->query('SELECT bssid FROM bssids');
    echo $mysql->error;
    $data = $res->fetch_all();
    $res->free();
    $c = count($data);
    $stmt = $mysql->stmt_init();
    $stmt->prepare('UPDATE bssids SET bssid1 = ? WHERE bssid = ?');
    foreach ($data as $i => $b) {
        $b1 = hex2bin(str_pad(dechex($b[0]), 12, '0', STR_PAD_LEFT));
        $stmt->bind_param('si', $b1, $b[0]);
        $stmt->execute();
        echo "\r$i/$c";
    }
    $mysql->commit();
    $stmt->close();
    echo " Done\n";

    // make bssids1 not null
    echo "Make bssid1 NOT NULL\n";
    $mysql->query('ALTER TABLE bssids MODIFY bssid1 binary(6) NOT NULL');

    // drop coulmn bssid
    echo "Drop bssid column\n";
    $mysql->query('ALTER TABLE bssids DROP COLUMN bssid');

    // rename bssid1 to bssid
    echo "Rename bssid1 to bssid\n";
    $mysql->query('ALTER TABLE bssids RENAME COLUMN bssid1 TO bssid');

    // add indexes
    echo "Add bssids indexes\n";
    $mysql->query('ALTER TABLE bssids ADD PRIMARY KEY (bssid)');
    $mysql->query('CREATE INDEX IDX_bssids_flags ON bssids(flags)');
    $mysql->query('CREATE INDEX IDX_bssids_ts ON bssids(ts)');
    $mysql->query('CREATE INDEX IDX_bssids_lat ON bssids(lat)');
    $mysql->query('CREATE INDEX IDX_bssids_lon ON bssids(lon)');
    $mysql->query('CREATE INDEX IDX_bssids_wifi3ts ON bssids(wifi3ts)');
}

echo "OK\n";
?>
