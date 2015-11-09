  --->>> Fingerprint Directories <<<---

Author: Mathew Fleisch
Created: 11/2015

Dependencies:
	- Perl
	- exiftool
	- openssl

Description:
This command line tool was created to recursively classify files by collecting
metadata about each file in one or more target directories. The tool collects
file size, checksums and uses the exiftool to gather other metadata. The results
are then available in a few standard formats. 

Required Arguments:

	-o --output-dir			Select a directory for the output files

	-t --target-dir			Space delimited list of directories to
	               			fingerprint.
Optional Arguments:

	-c --checksums			Space delimited list of what hash alg
					to include. Possible: "md5","sha1","sha256"
					All included by default.
	
	-f --format 			Comma delimited list of what format the
					output will be. Possible: "sql","csv","tsv"
					Default: "sql"
					
	-h --help			Help view. This dialog... What you're
					reading right now!

	-v --verbose			Verbose mode is false by default, and
	           			true is implied. 
					0 -> Default
					1 -> Show log messages
					2 -> Show raw sql commands

