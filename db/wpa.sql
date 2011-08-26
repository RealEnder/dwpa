-- phpMyAdmin SQL Dump
-- version 3.3.3
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Aug 26, 2011 at 06:16 PM
-- Server version: 5.1.54
-- PHP Version: 5.3.5-1ubuntu7.2

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


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
  `d_id` bigint(20) NOT NULL AUTO_INCREMENT,
  `dpath` varchar(256) NOT NULL,
  `dname` varchar(128) NOT NULL,
  `wcount` bigint(20) NOT NULL,
  `hits` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`d_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=5 ;

--
-- Dumping data for table `dicts`
--

INSERT INTO `dicts` (`d_id`, `dpath`, `dname`, `wcount`, `hits`) VALUES
(1, 'dict/cow.txt.gz', 'CoW', 15555, 0),
(2, 'dict/insidepro.txt.gz', 'InsidePro', 158142, 0),
(3, 'dict/openwall.txt.gz', 'OpenWall', 37711, 0),
(4, 'dict/os.txt.gz', 'Offensive Security', 435802, 0);

-- --------------------------------------------------------

--
-- Stand-in structure for view `get_dict`
--
CREATE TABLE IF NOT EXISTS `get_dict` (
`d_id` bigint(20)
,`dpath` varchar(256)
);
-- --------------------------------------------------------

--
-- Table structure for table `n2d`
--

CREATE TABLE IF NOT EXISTS `n2d` (
  `bssid` bigint(8) NOT NULL,
  `d_id` int(11) NOT NULL,
  `hits` int(11) NOT NULL DEFAULT '1',
  PRIMARY KEY (`bssid`,`d_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `n2d`
--


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
  `bssid` bigint(8) unsigned NOT NULL,
  `ssid` varchar(32) NOT NULL,
  `pass` varchar(64) DEFAULT NULL,
  `ip` int(10) unsigned NOT NULL,
  `sip` int(10) unsigned DEFAULT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `sts` timestamp NULL DEFAULT NULL,
  `n_state` tinyint(4) NOT NULL,
  `gw` int(11) NOT NULL DEFAULT '0',
  `d_id` bigint(20) DEFAULT NULL,
  `hits` int(11) NOT NULL,
  PRIMARY KEY (`bssid`),
  KEY `IDX_nets_ts` (`ts`),
  KEY `IDX_nets_ip` (`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Dumping data for table `nets`
--


-- --------------------------------------------------------

--
-- Stand-in structure for view `onets`
--
CREATE TABLE IF NOT EXISTS `onets` (
`bssid` bigint(8) unsigned
);
-- --------------------------------------------------------

--
-- Structure for view `get_dict`
--
DROP TABLE IF EXISTS `get_dict`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `get_dict` AS select `dicts`.`d_id` AS `d_id`,`dicts`.`dpath` AS `dpath` from ((`dicts` left join `n2d` on((`n2d`.`d_id` = `dicts`.`d_id`))) left join `onets` on((`n2d`.`bssid` = `onets`.`bssid`))) order by ifnull(`n2d`.`hits`,0),`dicts`.`wcount` limit 1;

-- --------------------------------------------------------

--
-- Structure for view `onets`
--
DROP TABLE IF EXISTS `onets`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `onets` AS select `nets`.`bssid` AS `bssid` from `nets` where (`nets`.`n_state` = 0) order by `nets`.`hits`,`nets`.`ts` limit 1;
