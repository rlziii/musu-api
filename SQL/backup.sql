# ************************************************************
# Sequel Pro SQL dump
# Version 4541
#
# http://www.sequelpro.com/
# https://github.com/sequelpro/sequelpro
#
# Host: mydb.c17vnanzumzs.us-east-1.rds.amazonaws.com (MySQL 5.6.37-log)
# Database: large
# Generation Time: 2018-05-01 00:44:16 +0000
# ************************************************************


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


# Dump of table Posts
# ------------------------------------------------------------

DROP TABLE IF EXISTS `Posts`;

CREATE TABLE `Posts` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `userID` int(11) unsigned NOT NULL,
  `bodyText` text,
  `imageURL` varchar(256) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `P_userID_FK` (`userID`),
  CONSTRAINT `P_userID_FK` FOREIGN KEY (`userID`) REFERENCES `Users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;



# Dump of table Posts_Tags
# ------------------------------------------------------------

DROP TABLE IF EXISTS `Posts_Tags`;

CREATE TABLE `Posts_Tags` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `postID` int(11) unsigned NOT NULL,
  `tagID` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `PT_postID_tagID_UK` (`postID`,`tagID`),
  KEY `PT_tagID_FK` (`tagID`),
  CONSTRAINT `PT_postID_FK` FOREIGN KEY (`postID`) REFERENCES `Posts` (`id`),
  CONSTRAINT `PT_tagID_FK` FOREIGN KEY (`tagID`) REFERENCES `Tags` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;



# Dump of table Tags
# ------------------------------------------------------------

DROP TABLE IF EXISTS `Tags`;

CREATE TABLE `Tags` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(256) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;



# Dump of table Tokens
# ------------------------------------------------------------

DROP TABLE IF EXISTS `Tokens`;

CREATE TABLE `Tokens` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `token` varchar(64) NOT NULL DEFAULT '',
  `userID` int(11) unsigned NOT NULL,
  `expiresAt` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `userID` (`userID`),
  CONSTRAINT `T_userID_FK` FOREIGN KEY (`userID`) REFERENCES `Users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;



# Dump of table Users
# ------------------------------------------------------------

DROP TABLE IF EXISTS `Users`;

CREATE TABLE `Users` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(60) NOT NULL DEFAULT '',
  `password` varchar(60) NOT NULL DEFAULT '',
  `firstName` varchar(60) DEFAULT NULL,
  `lastName` varchar(60) DEFAULT NULL,
  `emailAddress` varchar(60) DEFAULT NULL,
  `strengthCount` int(11) unsigned NOT NULL DEFAULT '0',
  `isGroup` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;



# Dump of table Users_Posts_Likes
# ------------------------------------------------------------

DROP TABLE IF EXISTS `Users_Posts_Likes`;

CREATE TABLE `Users_Posts_Likes` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `userID` int(11) unsigned NOT NULL,
  `postID` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `userID` (`userID`,`postID`),
  KEY `UPL_postID_FK` (`postID`),
  CONSTRAINT `UPL_postID_FK` FOREIGN KEY (`postID`) REFERENCES `Posts` (`id`),
  CONSTRAINT `UPL_userID_FK` FOREIGN KEY (`userID`) REFERENCES `Users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;



# Dump of table Users_Tags_Likes
# ------------------------------------------------------------

DROP TABLE IF EXISTS `Users_Tags_Likes`;

CREATE TABLE `Users_Tags_Likes` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `userID` int(11) unsigned NOT NULL,
  `tagID` int(11) unsigned NOT NULL,
  `strength` int(11) unsigned NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `userID` (`userID`,`tagID`),
  KEY `UTL_tagID_FK` (`tagID`),
  CONSTRAINT `UTL_tagID_FK` FOREIGN KEY (`tagID`) REFERENCES `Tags` (`id`),
  CONSTRAINT `UTL_userID_FK` FOREIGN KEY (`userID`) REFERENCES `Users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;




--
-- Dumping routines (PROCEDURE) for database 'large'
--
DELIMITER ;;

# Dump of PROCEDURE deletePost
# ------------------------------------------------------------

/*!50003 DROP PROCEDURE IF EXISTS `deletePost` */;;
/*!50003 SET SESSION SQL_MODE="NO_ENGINE_SUBSTITUTION"*/;;
/*!50003 CREATE*/ /*!50020 DEFINER=`root`@`%`*/ /*!50003 PROCEDURE `deletePost`(inputUserID INT, inputPostID INT)
BEGIN
	IF ((SELECT userID FROM Posts WHERE id = inputPostID) = inputUserID) THEN
	DELETE FROM Posts_Tags WHERE postID = inputPostID;
	DELETE FROM Users_Posts_Likes WHERE postID = inputPostID;
	DELETE FROM Posts WHERE id = inputPostID;
	END IF;
END */;;

/*!50003 SET SESSION SQL_MODE=@OLD_SQL_MODE */;;
DELIMITER ;

/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
