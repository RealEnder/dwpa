<?php
require_once('db.php');
require_once('common.php');

// Check if we've got user password submissions
if ($arr = build_cand($_POST)) {
    put_work($mysql, $arr);
}

echo '<h1>My networks</h1>';

$limit  = 20;
$k      = (isset($_COOKIE['key']) && valid_key($_COOKIE['key'])) ? $_COOKIE['key'] : '';
$offset = (isset($_GET['page']) && is_numeric($_GET['page'])) ? ((int)$_GET['page'] -1) * $limit : 0;
$page   = ($offset / $limit) + 1;

if ($k != '') {
    $stmt = $mysql->stmt_init();
    $stmt->prepare('SELECT SQL_CALC_FOUND_ROWS hex(nets.hash) as hash, nets.bssid, nets.ssid, nets.keyver, nets.message_pair, nets.pass, nets.algo, nets.nc, nets.endian, nets.n_state, nets.hits, n2u.ts, bssids.country
FROM nets
JOIN n2u ON nets.net_id=n2u.net_id
JOIN users ON users.u_id=n2u.u_id
LEFT JOIN bssids ON nets.bssid = bssids.bssid
WHERE users.userkey=UNHEX(?) AND n_state<2
ORDER BY nets.ts DESC, nets.bssid ASC
LIMIT ?,?');
    $stmt->bind_param('sii', $k, $offset, $limit);
    $stmt->execute();
    $result = $stmt->get_result();
    $datas = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();

    $result = $mysql->query('SELECT FOUND_ROWS()');
    $total = $result->fetch_all(MYSQLI_NUM);
    $result->free();

    $mysql->close();

    write_nets($datas);

    // download all found
    echo "<a href='?api&dl=1' class='btn'>Download all founds</a><br/><br/>";

    // paging
    $total = $total[0][0];
    echo "<div class='pagination'>";
    for ($i=1; $i<ceil($total / $limit) + 1; ++$i) {
        if ($page == $i) {
            echo "<span class='btn active'>$i</span>";
        } else {
            echo "<a href='?my_nets&page=$i' class='btn'>$i</a>";
        }
    }
}
?>
