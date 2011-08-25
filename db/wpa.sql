-- phpMyAdmin SQL Dump
-- version 3.3.3
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Aug 25, 2011 at 06:00 PM
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
  `d_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`bssid`),
  KEY `IDX_nets_ts` (`ts`),
  KEY `IDX_nets_ip` (`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
