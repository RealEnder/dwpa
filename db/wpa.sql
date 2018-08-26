SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";

--
-- Database: `wpa`
--

-- --------------------------------------------------------

--
-- Table structure for table `dicts`
--

CREATE TABLE IF NOT EXISTS `dicts` (
  `d_id` smallint(5) UNSIGNED NOT NULL AUTO_INCREMENT,
  `dpath` varchar(256) NOT NULL,
  `dhash` binary(16) DEFAULT NULL,
  `dname` varchar(128) NOT NULL,
  `wcount` int(10) UNSIGNED NOT NULL,
  `hits` int(10) UNSIGNED NOT NULL DEFAULT '0',
  PRIMARY KEY (`d_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- RELATIONSHIPS FOR TABLE `dicts`:
--

-- --------------------------------------------------------

--
-- Table structure for table `n2d`
--

CREATE TABLE IF NOT EXISTS `n2d` (
  `net_id` bigint(15) NOT NULL,
  `d_id` smallint(5) UNSIGNED NOT NULL,
  `hkey` binary(16) DEFAULT NULL COMMENT 'get_work key',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`net_id`,`d_id`),
  KEY `IDX_n2d_ts` (`ts`),
  KEY `IDX_n2d_net_id` (`net_id`),
  KEY `IDX_n2d_hkey` (`hkey`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- RELATIONSHIPS FOR TABLE `n2d`:
--   `d_id`
--       `dicts` -> `d_id`
--   `net_id`
--       `nets` -> `net_id`
--

--
-- Triggers `n2d`
--
DELIMITER $$
CREATE TRIGGER `TRG_n2d` AFTER INSERT ON `n2d` FOR EACH ROW BEGIN
    UPDATE nets SET hits=hits+1 WHERE nets.net_id=NEW.net_id;
    UPDATE dicts SET hits=hits+1 WHERE dicts.d_id=NEW.d_id;
END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `TRG_n2d_delete` AFTER DELETE ON `n2d` FOR EACH ROW BEGIN
    DECLARE vn_state tinyint(1);

    SELECT n_state FROM nets WHERE net_id=OLD.net_id INTO vn_state;
    IF (vn_state=0) THEN
        UPDATE dicts SET hits=hits-1 WHERE d_id=OLD.d_id;
        UPDATE nets SET hits=hits-1 WHERE net_id=OLD.net_id;
    END IF;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `n2u`
--

CREATE TABLE IF NOT EXISTS `n2u` (
  `net_id` bigint(15) NOT NULL,
  `u_id` bigint(15) NOT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`net_id`,`u_id`) USING BTREE,
  KEY `IDX_n2u_u_id` (`u_id`),
  KEY `IDX_n2u_net_id` (`net_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='nets2users relation';

--
-- RELATIONSHIPS FOR TABLE `n2u`:
--   `net_id`
--       `nets` -> `net_id`
--   `u_id`
--       `users` -> `u_id`
--

-- --------------------------------------------------------

--
-- Table structure for table `nets`
--

CREATE TABLE IF NOT EXISTS `nets` (
  `net_id` bigint(15) NOT NULL AUTO_INCREMENT,
  `s_id` bigint(15) NOT NULL,
  `bssid` bigint(15) UNSIGNED NOT NULL COMMENT 'AP BSSID unsigned integer',
  `mac_sta` bigint(15) UNSIGNED NOT NULL COMMENT 'Station mac address',
  `ssid` varbinary(32) NOT NULL COMMENT 'AP ESSID',
  `pass` varbinary(64) DEFAULT NULL COMMENT 'Pre-Shared Key (PSK)',
  `pmk` binary(32) DEFAULT NULL COMMENT 'Pairwise Master Key (PMK)',
  `algo` varchar(32) DEFAULT NULL,
  `hash` binary(16) NOT NULL COMMENT 'Partial md5 on hccapx or full md5 over PMKID line',
  `struct` varbinary(393) NOT NULL COMMENT 'hccapx or pmkid struct',
  `message_pair` tinyint(3) UNSIGNED NOT NULL COMMENT 'message_pair from hccapx',
  `keyver` tinyint(3) UNSIGNED NOT NULL COMMENT 'keyver from hccapx 1-WPA 2-WPA2 3-WPA2 AES-128-CMAC 100-PMKID',
  `nc` smallint(6) DEFAULT NULL COMMENT 'Nonce correction',
  `endian` enum('BE','LE') DEFAULT NULL COMMENT 'Endianness if detected from nonce correction',
  `sip` int(10) UNSIGNED DEFAULT NULL COMMENT 'PSK submitter IP',
  `sts` timestamp NULL DEFAULT NULL COMMENT 'PSK submission timestamp',
  `n_state` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'False - not cracked, True - cracked',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'submission timestamp',
  `hits` smallint(5) UNSIGNED NOT NULL DEFAULT '0' COMMENT 'Attempts count',
  PRIMARY KEY (`net_id`),
  UNIQUE KEY `IDX_nets_hash` (`hash`) USING BTREE,
  KEY `IDX_nets_bssid` (`bssid`),
  KEY `IDX_nets_n_state` (`n_state`),
  KEY `FK_nets_submissions` (`s_id`),
  KEY `IDX_nets_mac_sta` (`mac_sta`),
  KEY `IDX_nets_ssid` (`ssid`),
  KEY `IDX_nets_algo` (`algo`),
  KEY `IDX_nets_sts` (`sts`),
  KEY `IDX_nets_keyver` (`keyver`),
  KEY `IDX_nets_keyver_n_state` (`keyver`, `n_state`),
  KEY `IDX_nets_n_state_hits_ts_algo` (`n_state`,`hits`,`ts`,`algo`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- RELATIONSHIPS FOR TABLE `nets`:
--   `s_id`
--       `submissions` -> `s_id`
--

-- --------------------------------------------------------

--
-- Table structure for table `rkg`
--

CREATE TABLE `rkg` (
  `net_id` bigint(15) NOT NULL,
  `algo` varchar(32) NOT NULL COMMENT 'Identified algo',
  `pass` varbinary(64) NOT NULL COMMENT 'PSK candidate from rkg',
  `n_state` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'Successful PSK candidate',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `UNC_rkg_net_id_algo_pass` (`net_id`,`algo`,`pass`) USING BTREE,
  KEY `IDX_rkg_net_id` (`net_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `stats`
--

CREATE TABLE IF NOT EXISTS `stats` (
  `pname` varchar(20) NOT NULL,
  `pvalue` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`pname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- RELATIONSHIPS FOR TABLE `stats`:
--

-- --------------------------------------------------------

--
-- Table structure for table `submissions`
--

CREATE TABLE IF NOT EXISTS `submissions` (
  `s_id` bigint(15) NOT NULL AUTO_INCREMENT,
  `localfile` varchar(1024) NOT NULL COMMENT 'Local capture full path',
  `ip` int(10) UNSIGNED NOT NULL COMMENT 'Submission IP',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Submission timestamp',
  PRIMARY KEY (`s_id`),
  UNIQUE KEY `IDX_UNC_localfile` (`localfile`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='Capture file submissions';

--
-- RELATIONSHIPS FOR TABLE `submissions`:
--

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `u_id` bigint(15) NOT NULL AUTO_INCREMENT,
  `userkey` binary(16) NOT NULL,
  `mail` varchar(500) CHARACTER SET latin1 COLLATE latin1_general_ci DEFAULT NULL,
  `ip` int(10) UNSIGNED NOT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`u_id`),
  UNIQUE KEY `IDX_users_userkey` (`userkey`),
  UNIQUE KEY `IDX_users_mail` (`mail`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- RELATIONSHIPS FOR TABLE `users`:
--

-- --------------------------------------------------------

--
-- Constraints for dumped tables
--

--
-- Constraints for table `n2d`
--
ALTER TABLE `n2d`
  ADD CONSTRAINT `FK_n2d_dicts_d_id` FOREIGN KEY (`d_id`) REFERENCES `dicts` (`d_id`),
  ADD CONSTRAINT `FK_n2d_nets_net_id` FOREIGN KEY (`net_id`) REFERENCES `nets` (`net_id`);

--
-- Constraints for table `n2u`
--
ALTER TABLE `n2u`
  ADD CONSTRAINT `FK_n2u_nets_net_id` FOREIGN KEY (`net_id`) REFERENCES `nets` (`net_id`),
  ADD CONSTRAINT `FK_n2u_users_u_id` FOREIGN KEY (`u_id`) REFERENCES `users` (`u_id`);

--
-- Constraints for table `nets`
--
ALTER TABLE `nets`
  ADD CONSTRAINT `FK_nets_submissions_s_id` FOREIGN KEY (`s_id`) REFERENCES `submissions` (`s_id`);

--
-- Constraints for table `rkg`
--
ALTER TABLE `rkg`
  ADD CONSTRAINT `FK_rkg_nets_net_id` FOREIGN KEY (`net_id`) REFERENCES `nets` (`net_id`);

DELIMITER $$
--
-- Events
--
CREATE EVENT `e_stats` ON SCHEDULE EVERY 1 HOUR ON COMPLETION NOT PRESERVE ENABLE COMMENT 'Computes stats' DO BEGIN
UPDATE stats SET pvalue=(SELECT count(1) FROM n2d WHERE ts >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY)) WHERE pname='24getwork';
UPDATE stats SET pvalue=(SELECT sum(wcount) FROM n2d, dicts WHERE ts >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY) AND n2d.d_id=dicts.d_id) WHERE pname='24psk';
UPDATE stats SET pvalue=(SELECT count(1) FROM nets WHERE sts >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY) AND n_state=1) WHERE pname='24founds';
UPDATE stats SET pvalue=(SELECT count(1) FROM nets WHERE ts >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY)) WHERE pname='24sub';
UPDATE stats SET pvalue=(SELECT nc*wc FROM (SELECT SUM(wcount) AS wc FROM dicts) d, (SELECT COUNT(1) AS nc FROM nets WHERE n_state=0) n) WHERE pname='words';
UPDATE stats SET pvalue=(SELECT SUM(dicts.wcount) FROM n2d, dicts WHERE dicts.d_id = n2d.d_id) WHERE pname='triedwords';
END$$

CREATE EVENT `e_cleanup_n2d` ON SCHEDULE EVERY 1 HOUR ON COMPLETION NOT PRESERVE ENABLE DO DELETE FROM n2d WHERE hkey IS NOT NULL AND TIMESTAMPDIFF(DAY, ts, CURRENT_TIMESTAMP) > 0$$
