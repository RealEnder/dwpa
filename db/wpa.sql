-- phpMyAdmin SQL Dump
-- version 3.4.5
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Sep 18, 2011 at 12:53 PM
-- Server version: 5.1.54
-- PHP Version: 5.3.5-1ubuntu7.2

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `wpa`
--

-- --------------------------------------------------------

--
-- Table structure for table `dicts`
--

CREATE TABLE IF NOT EXISTS `dicts` (
  `d_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `dpath` varchar(256) NOT NULL,
  `dname` varchar(128) NOT NULL,
  `wcount` int(10) unsigned NOT NULL,
  `hits` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`d_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=14 ;

-- --------------------------------------------------------

--
-- Stand-in structure for view `get_dict`
--
CREATE TABLE IF NOT EXISTS `get_dict` (
`d_id` bigint(20) unsigned
,`dpath` varchar(256)
);
-- --------------------------------------------------------

--
-- Table structure for table `n2d`
--

CREATE TABLE IF NOT EXISTS `n2d` (
  `bssid` bigint(15) NOT NULL,
  `d_id` int(11) NOT NULL,
  `hits` int(11) NOT NULL DEFAULT '1',
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`bssid`,`d_id`),
  KEY `bssid` (`bssid`),
  KEY `ts` (`ts`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Triggers `n2d`
--
DROP TRIGGER IF EXISTS `TRG_n2d`;
DELIMITER //
CREATE TRIGGER `TRG_n2d` BEFORE INSERT ON `n2d`
 FOR EACH ROW BEGIN
    UPDATE nets SET hits=hits+1 WHERE nets.bssid=NEW.bssid;
    UPDATE dicts SET hits=hits+1 WHERE dicts.d_id=NEW.d_id;
END
//
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `nets`
--

CREATE TABLE IF NOT EXISTS `nets` (
  `bssid` bigint(15) unsigned NOT NULL,
  `ssid` varchar(32) NOT NULL,
  `pass` varchar(64) DEFAULT NULL,
  `ip` int(10) unsigned NOT NULL,
  `sip` int(10) unsigned DEFAULT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `sts` timestamp NULL DEFAULT NULL,
  `n_state` tinyint(1) unsigned NOT NULL,
  `u_id` bigint(20) DEFAULT NULL,
  `hits` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`bssid`),
  KEY `IDX_nets_ts` (`ts`),
  KEY `IDX_nets_ip` (`ip`),
  KEY `u_id` (`u_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Stand-in structure for view `onets`
--
CREATE TABLE IF NOT EXISTS `onets` (
`bssid` bigint(15) unsigned
);
-- --------------------------------------------------------

--
-- Stand-in structure for view `onets_dicts`
--
CREATE TABLE IF NOT EXISTS `onets_dicts` (
`bssid` bigint(15)
,`d_id` int(11)
,`hits` int(11)
);
-- --------------------------------------------------------

--
-- Table structure for table `stats`
--

CREATE TABLE IF NOT EXISTS `stats` (
  `pname` varchar(20) NOT NULL,
  `pvalue` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`pname`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `u_id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ukey` char(32) NOT NULL,
  `mail` varchar(500) DEFAULT NULL,
  `ip` int(10) unsigned NOT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`u_id`),
  UNIQUE KEY `key` (`ukey`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=8 ;

-- --------------------------------------------------------

--
-- Structure for view `get_dict`
--
DROP TABLE IF EXISTS `get_dict`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `get_dict` AS select `d`.`d_id` AS `d_id`,`d`.`dpath` AS `dpath` from (`dicts` `d` left join `onets_dicts` `od` on((`d`.`d_id` = `od`.`d_id`))) order by ifnull(`od`.`hits`,0),`d`.`wcount`;

-- --------------------------------------------------------

--
-- Structure for view `onets`
--
DROP TABLE IF EXISTS `onets`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `onets` AS select `nets`.`bssid` AS `bssid` from `nets` where (`nets`.`n_state` = 0) order by `nets`.`hits`,`nets`.`ts` limit 1;

-- --------------------------------------------------------

--
-- Structure for view `onets_dicts`
--
DROP TABLE IF EXISTS `onets_dicts`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `onets_dicts` AS select `n2d`.`bssid` AS `bssid`,`n2d`.`d_id` AS `d_id`,`n2d`.`hits` AS `hits` from (`n2d` join `onets` `o`) where (`n2d`.`bssid` = `o`.`bssid`);

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
