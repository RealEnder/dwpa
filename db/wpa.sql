SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";

--
-- Database: `wpa`
--

-- --------------------------------------------------------

--
-- Table structure for table `bssids`
--

CREATE TABLE IF NOT EXISTS `bssids` (
  `bssid` bigint UNSIGNED NOT NULL COMMENT 'BSSID of the network',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Record timestamp',
  `flags` tinyint UNSIGNED NOT NULL DEFAULT '0' COMMENT 'Bitflags, positions: 1 - 3wifi hit, 2 - wigle hit',
  `wifi3ts` timestamp NULL DEFAULT NULL COMMENT 'Last check for PSK in 3wifi DB',
  `wiglets` timestamp NULL DEFAULT NULL COMMENT 'Last check for location in wigle DB',
  `lat` decimal(10,8) DEFAULT NULL COMMENT 'Latitude',
  `lon` decimal(11,8) DEFAULT NULL COMMENT 'Longitude',
  `country` char(2) DEFAULT NULL COMMENT '2-letter ISO CC',
  `region` varchar(1000) DEFAULT NULL COMMENT 'Reported region',
  `city` varchar(1000) DEFAULT NULL COMMENT 'Reported city',
  PRIMARY KEY (`bssid`),
  KEY `IDX_bssids_flags` (`flags`),
  KEY `IDX_bssids_lat` (`lat`) USING BTREE,
  KEY `IDX_bssids_lon` (`lon`),
  KEY `IDX_bssids_wifi3ts` (`wifi3ts`) USING BTREE,
  KEY `IDX_bssids_ts` (`ts`),
  KEY `IDX_bssids_country` (`country`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- RELATIONSHIPS FOR TABLE `bssids`:
--

-- --------------------------------------------------------

--
-- Table structure for table `dicts`
--

CREATE TABLE IF NOT EXISTS `dicts` (
  `d_id` smallint UNSIGNED NOT NULL AUTO_INCREMENT,
  `dpath` varchar(256) NOT NULL,
  `dhash` binary(16) DEFAULT NULL,
  `dname` varchar(128) NOT NULL,
  `rules` mediumtext CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci COMMENT 'hashcat rules for the dict, \n separated',
  `wcount` int UNSIGNED NOT NULL,
  `hits` int UNSIGNED NOT NULL DEFAULT '0',
  PRIMARY KEY (`d_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- RELATIONSHIPS FOR TABLE `dicts`:
--

-- --------------------------------------------------------

--
-- Table structure for table `ks`
--

CREATE TABLE IF NOT EXISTS `ks` (
  `ks_id` bigint NOT NULL AUTO_INCREMENT,
  `ssidre` varchar(500) DEFAULT NULL,
  `passre` varchar(500) DEFAULT NULL,
  `note` varchar(10000) DEFAULT NULL,
  PRIMARY KEY (`ks_id`),
  UNIQUE KEY `ks_ssidre_IDX` (`ssidre`,`passre`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COMMENT='Default regexp keyspace for ssid and pass';

--
-- RELATIONSHIPS FOR TABLE `ks`:
--

-- --------------------------------------------------------

--
-- Table structure for table `n2d`
--

CREATE TABLE IF NOT EXISTS `n2d` (
  `net_id` bigint NOT NULL,
  `d_id` smallint UNSIGNED NOT NULL,
  `hkey` binary(16) DEFAULT NULL COMMENT 'get_work key 	',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`net_id`,`d_id`),
  KEY `IDX_n2d_ts` (`ts`),
  KEY `IDX_n2d_net_id` (`net_id`),
  KEY `IDX_n2d_d_id` (`d_id`),
  KEY `IDX_n2d_hkey` (`hkey`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

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
    IF ((SELECT n_state FROM nets WHERE net_id=OLD.net_id)=0) THEN
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
  `net_id` bigint NOT NULL,
  `u_id` bigint NOT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`net_id`,`u_id`) USING BTREE,
  KEY `IDX_n2u_u_id` (`u_id`),
  KEY `IDX_n2u_net_id` (`net_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COMMENT='nets2users relation';

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
  `net_id` bigint NOT NULL AUTO_INCREMENT,
  `s_id` bigint NOT NULL,
  `bssid` bigint UNSIGNED NOT NULL COMMENT 'AP BSSID',
  `mac_sta` bigint UNSIGNED NOT NULL COMMENT 'Station mac address',
  `ssid` varbinary(32) NOT NULL COMMENT 'AP SSID',
  `pass` varbinary(64) DEFAULT NULL COMMENT 'Pre-Shared Key (PSK)',
  `pmk` binary(32) DEFAULT NULL COMMENT 'Pairwise Master Key (PMK)',
  `algo` varchar(32) CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL COMMENT 'Identified algo',
  `hash` binary(16) NOT NULL COMMENT 'MD5 value, based on hashline',
  `struct` varchar(2000) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL COMMENT 'm22000 hashline',
  `message_pair` tinyint UNSIGNED DEFAULT NULL COMMENT 'message_pair value',
  `keyver` tinyint UNSIGNED NOT NULL COMMENT '1-WPA 2-WPA2 3-WPA2 AES-128-CMAC 100-PMKID',
  `nc` smallint DEFAULT NULL COMMENT 'Nonce error correction',
  `endian` enum('BE','LE') CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL COMMENT 'Endianness if detected from nonce error correction',
  `sip` int UNSIGNED DEFAULT NULL COMMENT 'PSK submitter IP',
  `sts` timestamp NULL DEFAULT NULL COMMENT 'PSK submission timestamp',
  `n_state` tinyint(1) NOT NULL DEFAULT '0' COMMENT '0 - not cracked, 1 - cracked, 2 - uncrackable',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Submission timestamp',
  `hits` smallint UNSIGNED NOT NULL DEFAULT '0' COMMENT 'Attempts count',
  PRIMARY KEY (`net_id`),
  UNIQUE KEY `IDX_nets_hash` (`hash`),
  KEY `FK_nets_submissions` (`s_id`),
  KEY `IDX_nets_bssid` (`bssid`),
  KEY `IDX_nets_n_state` (`n_state`),
  KEY `IDX_nets_mac_sta` (`mac_sta`),
  KEY `IDX_nets_ssid` (`ssid`),
  KEY `IDX_nets_algo` (`algo`),
  KEY `IDX_nets_sts` (`sts`),
  KEY `IDX_nets_ts` (`ts`),
  KEY `IDX_nets_keyver` (`keyver`),
  KEY `IDX_nets_pmk` (`pmk`),
  KEY `IDX_nets_keyver_n_state` (`keyver`,`n_state`),
  KEY `IDX_nets_n_state_hits_ts_algo` (`n_state`,`hits`,`ts`,`algo`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- RELATIONSHIPS FOR TABLE `nets`:
--   `s_id`
--       `submissions` -> `s_id`
--

--
-- Triggers `nets`
--
DELIMITER $$
CREATE TRIGGER `TRG_nets_bssids` AFTER INSERT ON `nets` FOR EACH ROW BEGIN
    INSERT IGNORE INTO bssids(bssid, ts) VALUES(NEW.bssid, NEW.ts);
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `p2s`
--

CREATE TABLE IF NOT EXISTS `p2s` (
  `pr_id` bigint NOT NULL,
  `s_id` bigint NOT NULL,
  PRIMARY KEY (`pr_id`,`s_id`),
  KEY `p2s_submissions_FK` (`s_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- RELATIONSHIPS FOR TABLE `p2s`:
--   `pr_id`
--       `prs` -> `pr_id`
--   `s_id`
--       `submissions` -> `s_id`
--

-- --------------------------------------------------------

--
-- Table structure for table `prs`
--

CREATE TABLE IF NOT EXISTS `prs` (
  `pr_id` bigint NOT NULL AUTO_INCREMENT,
  `ssid` varbinary(32) NOT NULL,
  PRIMARY KEY (`pr_id`),
  UNIQUE KEY `prs_ssid_IDX` (`ssid`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- RELATIONSHIPS FOR TABLE `prs`:
--

-- --------------------------------------------------------

--
-- Table structure for table `rkg`
--

CREATE TABLE IF NOT EXISTS `rkg` (
  `net_id` bigint NOT NULL,
  `algo` varchar(32) NOT NULL COMMENT 'Identified algo',
  `pass` varbinary(64) NOT NULL COMMENT 'PSK candidate from rkg',
  `n_state` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'Successful PSK candidate',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `UNC_rkg_net_id_algo_pass` (`net_id`,`algo`,`pass`) USING BTREE,
  KEY `IDX_rkg_net_id` (`net_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- RELATIONSHIPS FOR TABLE `rkg`:
--   `net_id`
--       `nets` -> `net_id`
--

-- --------------------------------------------------------

--
-- Table structure for table `stats`
--

CREATE TABLE IF NOT EXISTS `stats` (
  `pname` varchar(20) NOT NULL,
  `pvalue` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`pname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- RELATIONSHIPS FOR TABLE `stats`:
--

-- --------------------------------------------------------

--
-- Table structure for table `submissions`
--

CREATE TABLE IF NOT EXISTS `submissions` (
  `s_id` bigint NOT NULL AUTO_INCREMENT,
  `localfile` varchar(1024) NOT NULL COMMENT 'Local capture full path',
  `hash` binary(16) NOT NULL COMMENT 'Capture hash',
  `ip` int UNSIGNED NOT NULL COMMENT 'Submission IP',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Submission timestamp',
  PRIMARY KEY (`s_id`),
  UNIQUE KEY `UNC_submissions_hash` (`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COMMENT='Capture file submissions';

--
-- RELATIONSHIPS FOR TABLE `submissions`:
--

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `u_id` bigint NOT NULL AUTO_INCREMENT,
  `userkey` binary(16) NOT NULL COMMENT 'User key to access results and API',
  `linkkey` binary(16) DEFAULT NULL COMMENT 'Confirmation link key',
  `linkkeyts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Timestamp of last link sending',
  `mail` varchar(500) CHARACTER SET latin1 COLLATE latin1_general_ci DEFAULT NULL,
  `ip` int UNSIGNED NOT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`u_id`),
  UNIQUE KEY `UNC_users_userkey` (`userkey`) USING BTREE,
  UNIQUE KEY `UNC_users_mail` (`mail`) USING BTREE,
  UNIQUE KEY `UNC_users_linkkey` (`linkkey`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- RELATIONSHIPS FOR TABLE `users`:
--

--
-- Constraints for dumped tables
--

--
-- Constraints for table `n2d`
--
ALTER TABLE `n2d`
  ADD CONSTRAINT `FK_n2d_dicts_d_id` FOREIGN KEY (`d_id`) REFERENCES `dicts` (`d_id`) ON DELETE RESTRICT ON UPDATE RESTRICT,
  ADD CONSTRAINT `FK_n2d_nets_net_id` FOREIGN KEY (`net_id`) REFERENCES `nets` (`net_id`);

--
-- Constraints for table `n2u`
--
ALTER TABLE `n2u`
  ADD CONSTRAINT `FK_n2u_nets_net_id` FOREIGN KEY (`net_id`) REFERENCES `nets` (`net_id`),
  ADD CONSTRAINT `FK_n2u_users_u_id` FOREIGN KEY (`u_id`) REFERENCES `users` (`u_id`) ON DELETE RESTRICT ON UPDATE RESTRICT;

--
-- Constraints for table `nets`
--
ALTER TABLE `nets`
  ADD CONSTRAINT `FK_nets_submissions_s_id` FOREIGN KEY (`s_id`) REFERENCES `submissions` (`s_id`);

--
-- Constraints for table `p2s`
--
ALTER TABLE `p2s`
  ADD CONSTRAINT `p2s_prs_FK` FOREIGN KEY (`pr_id`) REFERENCES `prs` (`pr_id`),
  ADD CONSTRAINT `p2s_submissions_FK` FOREIGN KEY (`s_id`) REFERENCES `submissions` (`s_id`);

--
-- Constraints for table `rkg`
--
ALTER TABLE `rkg`
  ADD CONSTRAINT `FK_rkg_nets_net_id` FOREIGN KEY (`net_id`) REFERENCES `nets` (`net_id`);
COMMIT;

