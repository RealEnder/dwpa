-- phpMyAdmin SQL Dump
-- version 3.4.5
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Sep 18, 2011 at 05:47 PM
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

--
-- Dumping data for table `dicts`
--

INSERT INTO `dicts` (`d_id`, `dpath`, `dname`, `wcount`, `hits`) VALUES
(1, 'http://sec.stanev.org/dict/cow.txt.gz', 'CoW', 931005, 7307),
(2, 'http://sec.stanev.org/dict/insidepro.txt.gz', 'InsidePro', 7789778, 0),
(3, 'http://sec.stanev.org/dict/openwall.txt.gz', 'OpenWall', 1148592, 4873),
(4, 'http://sec.stanev.org/dict/os.txt.gz', 'Offensive Security', 34239072, 0),
(6, 'http://sec.stanev.org/dict/old_gold.txt.gz', 'Old gold', 1560185, 0),
(5, 'http://wpa-sec.stanev.org/dict/cracked.txt.gz', 'C-nets', 627, 7614),
(7, 'http://sec.stanev.org/dict/wp.txt.gz', 'Wikipedia en', 5927677, 0),
(8, 'http://sec.stanev.org/dict/ud.txt.gz', 'Slang', 510453, 7351),
(9, 'http://sec.stanev.org/dict/wpchit_bg.txt.gz', 'wp_chit bg', 1318369, 0),
(10, 'http://sec.stanev.org/dict/wp_de.txt.gz', 'Wikipedia de', 5430192, 0),
(11, 'http://sec.stanev.org/dict/wp_es.txt.gz', 'Wikipedia es', 1530155, 0),
(12, 'http://sec.stanev.org/dict/wp_fr.txt.gz', 'Wikipedia fr', 1295615, 0),
(13, 'http://sec.stanev.org/dict/wp_ru.txt.gz', 'Wikipedia ru', 2574162, 0);

--
-- Dumping data for table `stats`
--

INSERT INTO `stats` (`pname`, `pvalue`) VALUES
('nets', '8137'),
('cracked', '822'),
('24getwork', '871'),
('24psk', '847741470');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
