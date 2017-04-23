/**
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2017  Joshua M. David
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation in version 3 of the License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */


/*!40101 SET NAMES utf8 */;
/*!40101 SET SQL_MODE=''*/;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

CREATE DATABASE /*!32312 IF NOT EXISTS*/`jericho` /*!40100 DEFAULT CHARACTER SET utf8 */;
USE `jericho`;

/*Table structure for table `messages` */

DROP TABLE IF EXISTS `messages`;

CREATE TABLE `messages` (
  `message_id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'The primary key',
  `from_user` VARCHAR(10) DEFAULT NULL COMMENT 'Who the message is for',
  `message` VARCHAR(384) DEFAULT NULL COMMENT 'The ciphertext message and MAC concatenated',
  `read_by_alpha` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Alpha',
  `read_by_bravo` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Bravo',
  `read_by_charlie` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Charlie',
  `read_by_delta` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Delta',
  `read_by_echo` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Echo',
  `read_by_foxtrot` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Foxtrot',
  `read_by_golf` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Golf',
  PRIMARY KEY (`message_id`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

/*Data for the table `messages` */

/*Table structure for table `nonces` */

DROP TABLE IF EXISTS `nonces`;

CREATE TABLE `nonces` (
  `nonce_id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'An id for the table',
  `nonce_sent_timestamp` BIGINT(20) DEFAULT NULL COMMENT 'What time the nonce was sent by the user',
  `nonce` VARCHAR(128) DEFAULT NULL COMMENT 'The 512 bit nonce in hexadecimal symbols',
  PRIMARY KEY (`nonce_id`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

/*Data for the table `nonces` */

/*Table structure for table `settings` */

DROP TABLE IF EXISTS `settings`;

CREATE TABLE `settings` (
  `settings_id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'An id for the table',
  `test_connection` TINYINT(1) DEFAULT '1' COMMENT 'Value to test connection to database',
  `cleanup_last_run` BIGINT(10) DEFAULT NULL COMMENT 'When the cleanup task to clear read messages and old nonces was last run',
  PRIMARY KEY (`settings_id`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

/*Data for the table `settings` */

INSERT  INTO `settings`(`test_connection`,`cleanup_last_run`) VALUES (1,1399156649);

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;





/*!40101 SET NAMES utf8 */;
/*!40101 SET SQL_MODE=''*/;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
CREATE DATABASE /*!32312 IF NOT EXISTS*/`jericho_test` /*!40100 DEFAULT CHARACTER SET utf8 */;

USE `jericho_test`;

/*Table structure for table `messages` */

DROP TABLE IF EXISTS `messages`;

CREATE TABLE `messages` (
  `message_id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'The primary key',
  `from_user` VARCHAR(10) DEFAULT NULL COMMENT 'Who the message is for',
  `message` VARCHAR(384) DEFAULT NULL COMMENT 'The ciphertext message and MAC concatenated',
  `read_by_alpha` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Alpha',
  `read_by_bravo` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Bravo',
  `read_by_charlie` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Charlie',
  `read_by_delta` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Delta',
  `read_by_echo` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Echo',
  `read_by_foxtrot` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Foxtrot',
  `read_by_golf` TINYINT(1) DEFAULT '0' COMMENT 'Boolean for if the message has been read by user Golf',
  PRIMARY KEY (`message_id`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

/*Data for the table `messages` */

/*Table structure for table `nonces` */

DROP TABLE IF EXISTS `nonces`;

CREATE TABLE `nonces` (
  `nonce_id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'An id for the table',
  `nonce_sent_timestamp` BIGINT(20) DEFAULT NULL COMMENT 'What time the nonce was sent by the user',
  `nonce` VARCHAR(128) DEFAULT NULL COMMENT 'The 512 bit nonce in hexadecimal symbols',
  PRIMARY KEY (`nonce_id`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

/*Data for the table `nonces` */

/*Table structure for table `settings` */

DROP TABLE IF EXISTS `settings`;

CREATE TABLE `settings` (
  `settings_id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'An id for the table',
  `test_connection` TINYINT(1) DEFAULT '1' COMMENT 'Value to test connection to database',
  `cleanup_last_run` BIGINT(10) DEFAULT NULL COMMENT 'When the cleanup task to clear read messages and old nonces was last run',
  PRIMARY KEY (`settings_id`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

/*Data for the table `settings` */

INSERT  INTO `settings`(`test_connection`,`cleanup_last_run`) VALUES (1,1399156649);

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
