<?php
require_once('../db.php');
require_once('../common.php');

// Check if we've got user password submissions
if ($arr = build_cand($_POST)) {
    put_work($mysql, $arr);
}

echo '<h1>Search networks</h1>';

$search = '';
if (isset($_GET['search'])) {
    $search = $_GET['search'];
}

if (strlen($search) >= 3) {
    $k = '';
    if (isset($_COOKIE['key']) && valid_key($_COOKIE['key'])) {
        $k = $_COOKIE['key'];
    }

    // detect if we'll search for BSSID ot mac_sta
    $column = 'bssid';
    if (str_starts_with($search, 'client:')) {
        $search = trim(substr($search, 7));
        $column = 'mac_sta';
    }

    // search by BSSID or mac_sta
    if (valid_mac($search)) {
        $bssid = hex2bin($search);
        if ($k == $bosskey) {
            $sql = "SELECT HEX(hash) as hash, nets.bssid, ssid, keyver, message_pair, pass, algo, nc, endian, hits, nets.ts, n_state, country
FROM nets
LEFT JOIN bssids ON nets.bssid = bssids.bssid
WHERE nets.$column = ? AND n_state<2
ORDER BY ts DESC";
        } else {
            $sql = "SELECT HEX(hash) AS hash, bssid, ssid, keyver, message_pair, IF(n.u_id IS NULL, IF(pass IS NULL, NULL, 'Found'), pass) AS pass, algo, nc, endian, hits, ts, n_state, country
FROM (SELECT nets.*, country
      FROM nets
      LEFT JOIN bssids ON nets.bssid = bssids.bssid
      WHERE nets.$column = ? AND n_state<2
      ORDER BY nets.ts DESC
      LIMIT 20) AS n1
LEFT JOIN (SELECT n2u.net_id, users.u_id
           FROM n2u, users
           WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)) AS n
ON n.net_id=n1.net_id";
        }
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        if ($k == $bosskey)
            $stmt->bind_param('s', $bssid);
        else
            $stmt->bind_param('ss', $bssid, $k);
    // search by partial BSSID
    } elseif (valid_mac($search, 3)) {
        $bssid = hex2bin(substr($search, 0, 8));
        if ($k == $bosskey) {
            $sql = "SELECT HEX(hash) as hash, nets.bssid, ssid, keyver, message_pair, pass, algo, nc, endian, hits, nets.ts, n_state, country
FROM nets
LEFT JOIN bssids ON nets.bssid = bssids.bssid
WHERE nets.$column >> 24 = ? AND n_state<2
ORDER BY ts DESC";
        } else {
            $sql = "SELECT HEX(hash) as hash, bssid, ssid, keyver, message_pair, IF(n.u_id IS NULL, IF(pass IS NULL, NULL, 'Found'), pass) AS pass, algo, nc, endian, hits, ts, n_state, country
FROM (SELECT nets.*, country
      FROM nets
      LEFT JOIN bssids ON nets.bssid = bssids.bssid
      WHERE nets.$column >> 24 = ? AND n_state<2
      ORDER BY nets.ts DESC
      LIMIT 20) AS n1
LEFT JOIN (SELECT n2u.net_id, users.u_id
           FROM n2u, users
           WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)) AS n
ON n.net_id=n1.net_id";
        }
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        if ($k == $bosskey)
            $stmt->bind_param('s', $bssid);
        else
            $stmt->bind_param('ss', $bssid, $k);
    // search by SSID
    } else {
        $ssid = "$search%";
        if (strpos($search, '_') || strpos($search, '%')) {
            $ssid = $search;
        }
        if ($k == $bosskey) {
            $sql = "SELECT HEX(hash) as hash, nets.bssid, ssid, keyver, message_pair, pass, algo, nc, endian, hits, nets.ts, n_state, country
FROM nets
LEFT JOIN bssids ON nets.bssid = bssids.bssid
WHERE nets.ssid LIKE ? AND n_state<2
ORDER BY nets.ts DESC";
        } else {
            $sql = "SELECT HEX(hash) as hash, bssid, ssid, keyver, message_pair, IF(n.u_id IS NULL, IF(pass IS NULL, NULL, 'Found'), pass) AS pass, algo, nc, endian, hits, ts, n_state, country
FROM (SELECT nets.*, country
      FROM nets
      LEFT JOIN bssids ON nets.bssid = bssids.bssid
      WHERE nets.ssid LIKE ? AND n_state<2
      ORDER BY nets.ts DESC
      LIMIT 20) AS n1
LEFT JOIN (SELECT n2u.net_id, users.u_id
           FROM n2u, users
           WHERE n2u.u_id=users.u_id AND users.userkey=UNHEX(?)) AS n
ON n.net_id=n1.net_id";
        }
        $stmt = $mysql->stmt_init();
        $stmt->prepare($sql);
        if ($k == $bosskey)
            $stmt->bind_param('s', $ssid);
        else
            $stmt->bind_param('ss', $ssid, $k);
    }

    $stmt->execute();
    $result = $stmt->get_result();
    $datas = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    $mysql->close();

    write_nets($datas);
} else {
    echo 'Search for at least 3 chars or BSSID/OUI. Use "client:" to search by client MAC address/OUI.';
}
?>
