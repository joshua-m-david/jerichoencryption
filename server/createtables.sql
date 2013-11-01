/*
	Jericho Chat - Information-theoretically secure communications.
	Copyright (C) 2013  Joshua M. David

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation in version 3 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see [http://www.gnu.org/licenses/].
*/

/*!40101 SET NAMES utf8 */;
/*!40101 SET SQL_MODE=''*/;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

CREATE DATABASE /*!32312 IF NOT EXISTS*/`jericho` /*!40100 DEFAULT CHARACTER SET utf8 */;

USE `jericho`;

/* Table structure for table `messages` */
DROP TABLE IF EXISTS `messages`;

CREATE TABLE `messages` (
  `message_id` int(10) unsigned NOT NULL AUTO_INCREMENT COMMENT 'The primary key',
  `message_to` varchar(30) DEFAULT NULL COMMENT 'Who the message is for',
  `message` varchar(300) DEFAULT NULL COMMENT 'The ciphertext message',
  `message_authentication_code` varchar(128) DEFAULT NULL COMMENT 'The MAC for the message',
  PRIMARY KEY (`message_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/* Table structure for table `settings` */
DROP TABLE IF EXISTS `settings`;

CREATE TABLE `settings` (
  `test_connection` tinyint(1) DEFAULT '1' COMMENT 'Value to test connection to database',
  `auto_nuke_initiated` tinyint(1) DEFAULT '0' COMMENT 'Whether an auto nuke of all data has been initiated by the user'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/* Data for the table `settings` */
insert  into `settings`(`test_connection`,`auto_nuke_initiated`) values (1,0);

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;