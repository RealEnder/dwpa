-- phpMyAdmin SQL Dump
-- version 3.4.5
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Nov 20, 2011 at 09:24 AM
-- Server version: 5.1.54
-- PHP Version: 5.3.5-1ubuntu7.3

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
(1, 'http://sec.stanev.org/dict/cow.txt.gz', 'CoW', 930799, 12280),
(2, 'http://sec.stanev.org/dict/insidepro.txt.gz', 'InsidePro', 7788990, 0),
(3, 'http://sec.stanev.org/dict/openwall.txt.gz', 'OpenWall', 1148496, 12157),
(4, 'http://sec.stanev.org/dict/os.txt.gz', 'Offensive Security', 34036913, 0),
(6, 'http://sec.stanev.org/dict/old_gold.txt.gz', 'Old gold', 1560177, 10601),
(5, 'http://wpa-sec.stanev.org/dict/cracked.txt.gz', 'C-nets', 1095, 12825),
(7, 'http://sec.stanev.org/dict/wp.txt.gz', 'Wikipedia en', 5925979, 0),
(8, 'http://sec.stanev.org/dict/ud.txt.gz', 'Slang', 510315, 12296),
(9, 'http://sec.stanev.org/dict/wpchit_bg.txt.gz', 'wp_chit bg', 1318313, 11402),
(10, 'http://sec.stanev.org/dict/wp_de.txt.gz', 'Wikipedia de', 5429072, 0),
(11, 'http://sec.stanev.org/dict/wp_es.txt.gz', 'Wikipedia es', 1528843, 11370),
(12, 'http://sec.stanev.org/dict/wp_fr.txt.gz', 'Wikipedia fr', 1294686, 11708),
(13, 'http://sec.stanev.org/dict/wp_ru.txt.gz', 'Wikipedia ru', 2574086, 3359),
(14, 'http://sec.stanev.org/dict/used.txt.gz', 'Used', 9062908, 0),
(15, 'http://sec.stanev.org/dict/pinyin.txt.gz', 'Pinyin chinese', 61479, 11393);

--
-- Dumping data for table `stats`
--

INSERT INTO `stats` (`pname`, `pvalue`) VALUES
('nets', '12761'),
('cracked', '1489'),
('24getwork', '13089'),
('24psk', '3972098409');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
