CREATE TABLE `files` (
  `id` int(255) unsigned NOT NULL,
  `bundle_skip` tinyint(1) NOT NULL DEFAULT '0',
  `file` text,
  `filename` text,
  `filesize` int(255) DEFAULT NULL,
  `md5_checksum` varchar(33) DEFAULT NULL,
  `sha1_checksum` varchar(41) DEFAULT NULL,
  `sha256_checksum` varchar(65) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `md5_index` (`md5_checksum`),
  KEY `sha1_index` (`sha1_checksum`),
  KEY `sha256_index` (`sha256_checksum`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `metadata` (
  `id` int(255) unsigned NOT NULL AUTO_INCREMENT,
  `file_id` int(255) DEFAULT NULL,
  `key` varchar(200) DEFAULT NULL,
  `value` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2752 DEFAULT CHARSET=utf8;
