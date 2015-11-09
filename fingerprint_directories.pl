#!/usr/bin/perl

use strict;
use warnings;
my $start_run = time();

`exiftool -ver` or die "\n\nexiftool not installed...\n\n";
`openssl version` or die "\n\nopenssl not installed...\n\n";

my $output_dir = "";
my @target_dirs;
my @checksums;
my $target_offset = -1;
my $arg_offset = -1;
my $cksm_offset = -1;
my $run_md5 = 0;my $run_sha1 = 0;my $run_sha256 = 0;
my $md5;my $sha1;my $sha256;
my @possible_checksums = ("md5","sha1","sha256");
my $num_file = 0;
my $verbose = 0;
my $help_file = "./help_message.txt";
my $exclude_params = "./exclude_parameters.txt";
my $sql_file = "";my $csv_files = "";my $csv_meta = "";my $tsv_files = "";my $tsv_meta = "";my $log_file = "";my $err_file = "";
my $sql_fh;my $csvfiles_fh;my $csvmeta_fh;my $tsvfiles_fh;my $tsvmeta_fh;my $log_fh;my $err_fh;
my $sql_child = "";my $csvmeta_child = "";my $tsvmeta_child = "";my $csvfiles_child = "";my $tsvfiles_child = "";
my $sql_parent = "";my $csvfiles_parent = "";my $tsvfiles_parent = "";my $csvmeta_parent = "";my $tsvmeta_parent = ""; 
my $csv_parent;my $tsv_parent;
my $format = "sql";
my $source_id = 0;


my %ignore_params;
open my $handle, '<', $exclude_params;
chomp(my @ignore_metadata = <$handle>);
close $handle;
#Debug to verify @ignore_metadata is loading...
#print join(", ", @ignore_metadata);exit;

my $help_message;
open(my $fh, '<', $help_file) or die "cannot open file $help_file"; {
	local $/;
	$help_message = <$fh>;
}
close($fh);
#Debug to verify $help_message is loading...
#print $help_message;exit;

if(scalar(@ARGV) > 0) { 
	foreach my $arg (@ARGV) {
		#print "Arg[$arg_offset]: $arg\n";
		my $crnt = $ARGV[$arg_offset];
		my $next = $ARGV[$arg_offset+1];
		if($crnt =~ m/^-/) { 
			#Set Output Directory
			if($crnt =~ m/^-o$/ || $crnt =~ m/^--output-dir$/ || $crnt =~ m/^--output-dirs$/) {
				$next =~ s/\/$//g;
				if(-d $next) { $output_dir = $next; }
			#Set Target Dir(s)
			} elsif($crnt =~ m/^-t$/ || $crnt =~ m/^--target-dir$/ || $crnt =~ m/^--target-dirs$/) {
				$target_offset = $arg_offset;
			} elsif($crnt =~ m/^-s$/ || $crnt =~ m/^--source-id$/) {
				if($next =~ m/^-?\d+$/) { $source_id = $next; }
			} elsif($crnt =~ m/^-f$/ || $crnt =~ m/^--format$/) {
				$format = $next;
			} elsif($crnt =~ m/^-c$/ || $crnt =~ m/^--checksum$/ || $crnt =~ m/^--checksums$/) {
				$cksm_offset = $arg_offset;
			} elsif($crnt =~ m/^-v$/ || $crnt =~ m/^--verbose$/ ) { 
				if($next =~ m/^-?\d+$/) { 
					$verbose = $next; 
				} else { $verbose = 1; }
			} elsif($crnt =~ m/^-h$/ || $crnt =~ m/^--help$/ || $crnt =~ m/^--manual$/) { 
				print $help_message; exit;
			} else { print "\n\n **** Argument not recognized...\n\n\n$help_message"; exit; }
		}
		$arg_offset++;
	}
} else { 
	print "\n\n **** You must select an output directory and at least one target directory to fingerprint ****\n\n\n$help_message";
}

if(scalar(@ignore_metadata) > 0) { 
	if($source_id > 0) { 
		if(-d $output_dir) { 
			@checksums = get_checksums($cksm_offset, @ARGV);
			if($verbose) { print "Checksums: ".join(", ",@checksums)."\n\n"; }
	
			if($verbose) { print "Output Directory: $output_dir\n"; }
			if($format =~ m/sql/) { 
				$sql_file = "$output_dir/fingerprint_directories_".getLoggingTime().".sql";
				open($sql_fh, '>', $sql_file) or die "Could not open file $!";
			}
			if($format =~ m/csv/) { 
				$csv_files = "$output_dir/fingerprint_files_".getLoggingTime().".csv";
				$csv_meta = "$output_dir/fingerprint_metadata_".getLoggingTime().".csv";
				open($csvfiles_fh, '>', $csv_files) or die "Could not open file $!";
				open($csvmeta_fh, '>', $csv_meta) or die "Could not open file $!";
				print $csvfiles_fh "\"id\",\"source_id\",\"bundle_skip\",\"file\",\"filename\",\"md5_checksum\",\"sha1_checksum\",\"sha256_checksum\"\n";
				print $csvmeta_fh "\"file_id\",\"key\",\"value\"\n";
			}
			if($format =~ m/tsv/) { 
				$tsv_files = "$output_dir/fingerprint_files_".getLoggingTime().".tsv";
				$tsv_meta = "$output_dir/fingerprint_metadata_".getLoggingTime().".tsv";
				open($tsvfiles_fh, '>', $tsv_files) or die "Could not open file $!";
				open($tsvmeta_fh, '>', $tsv_meta) or die "Could not open file $!";
				print $tsvfiles_fh "id\tsource_id\tbundle_skip\tfile\tfilename\tmd5_checksum\tsha1_checksum\tsha256_checksum\n";
				print $tsvmeta_fh "file_id\tkey\tvalue\n";
			}
			$log_file = "$output_dir/fingerprint_log_".getLoggingTime().".txt";
			open($log_fh, '>', $log_file) or die "Could not open file $!";
			$err_file = "$output_dir/fingerprint_errors_".getLoggingTime().".txt";
			open($err_fh, '>', $err_file) or die "Could not open file $!";
	
			if($target_offset > -1) { 	
				if($verbose) { print "Target Offset: $target_offset\n"; }
				@target_dirs = verify_dirs($target_offset, @ARGV);
				if(scalar(@target_dirs) > 0) { 
					if($verbose) { print "Target Directories: ".join(", ", @target_dirs)."\n"; }
		
					%ignore_params = map { $_ => 1 } @ignore_metadata;
	
	
	
	
	
					#Cycle through target directories and pass each to process_files()
					foreach my $el (@target_dirs) { 
						print $el."\n";
						process_files($el);
					}
	
					my $end_run = time();
					my $run_time = $end_run - $start_run;
					print "Run Time: $run_time seconds\n";
					print $log_fh "Run Time: $run_time seconds\n";
					
					close $log_fh; 
					close $err_fh;
					if($format =~ m/sql/) { close $sql_fh; }
					if($format =~ m/csv/) { close $csvfiles_fh; close $csvmeta_fh; }
					if($format =~ m/tsv/) { close $tsvfiles_fh; close $tsvmeta_fh; }
				} else { print "\n\nThere were no target directories found...\n\n"; exit; }
			} else { print "\n\nThere were no target directories found...\n\n"; exit; }
		} else { print "\n\nThe output directory was not set...\n\n"; exit; } 
	} else { print "\n\nSource-id was not set...\n\n"; exit; }
} else { print "\n\nIgnore list could not be loaded...\n\n"; exit; }





#Functions...



sub process_files {
	my $path = shift;
	opendir (DIR, $path) or die "Unable to open $path: $!";
	my @files = grep { !/^\.{1,2}$/ } readdir (DIR);
	closedir (DIR);
	@files = map { $path . '/' . $_ } @files;
	for (@files) {
		my $crnt_file = $_;
		my $filepath = AddSlashes($_);	
		$crnt_file =~ s/$path\///g;
		if (-d $_) {
			if($_ =~ m/\.app/ || $_ =~ m/\.key/ || $_ =~ m/\.pkg/ || $_ =~ m/\.pages/) { 
				$num_file++;
				my $msg = "Skip apps, packages, keynotes and pages: $_\n";
				print $log_fh $msg;
				print $err_fh $msg;
				if($verbose) { print $msg; } 
				for(my $i = 0; $i < scalar(@checksums); $i++) { 
					my $crnt_checksum = $checksums[$i];
					
					if($crnt_checksum =~ m/md5/i) { 
						$run_md5 = 1;
					} elsif($crnt_checksum =~ m/sha1/i) { 
						$run_sha1 = 1;	
					} elsif($crnt_checksum =~ m/sha256/i) { 
						$run_sha256 = 1;
					}
				}
				if($format =~ m/csv/) { 
					$csv_parent = "\"".escape_quote($num_file)."\","
						.escape_quote($source_id).","
						."\"1\","
						."\"".escape_quote($_)."\","
						."\"".escape_quote($crnt_file)."\""
						.($run_md5 > 0 ? "," : "")
						.($run_sha1 > 0 ? "," : "")
						.($run_sha256 > 0 ? "," : "")
						."\n";
					print $csvfiles_fh $csv_parent;
				}
				if($format =~ m/tsv/) { 
					$tsv_parent = escape_quote($num_file)."\t"
						.escape_quote($source_id)."\t"
						."1\t"
						.escape_quote($_)."\t"
						.escape_quote($crnt_file)
						.($run_md5 > 0 ? "\t" : "")
						.($run_sha1 > 0 ? "\t" : "")
						.($run_sha256 > 0 ? "\t" : "")
						."\n";
					print $tsvfiles_fh $tsv_parent;
				}
				if($format =~ m/sql/) { 
					 $sql_parent = "INSERT INTO files "
					."(`id`, `source_id`, `bundle_skip`, `file`, `filename`) "
					."VALUES "
					."("
						."\"".escape_quote($num_file)."\","
						."\"".escape_quote($source_id)."\","
						."\"1\","
						."\"".escape_quote($_)."\","
						."\"".escape_quote($crnt_file)."\""
					.");\n";
					print $sql_fh $sql_parent;
				}
				if($verbose > 1) { print $sql_parent; }
			} else {
				process_files ($_);
			}
		} else { 
			if($crnt_file =~ m/^\.{1,2}/ ) {
				if($verbose) { print "Skip hidden file: ".$_."\n"; }
				print $err_fh "Skip hidden file: ".$_."\n";
				print $log_fh "Skip hidden file: ".$_."\n";
			} else { 
				$num_file++;
				print $log_fh "\n".$crnt_file."\n";
				
				#Grab filesize from exiftool
				my $filesize = `exiftool -t -filesize# $filepath`;
				$filesize =~ s/^.*\t//g;
				$filesize =~ s/\s//g;
				print $log_fh "Filesize: $filesize\n";

				
				for(my $i = 0; $i < scalar(@checksums); $i++) { 
					my $crnt_checksum = $checksums[$i];
					
					if($crnt_checksum =~ m/md5/i) { 
						$run_md5 = 1;
						#Calculate md5 checksum
						$md5 = `openssl md5 $filepath`;
						$md5 =~ s/^.*=\s//g;
						$md5 =~ s/\s//g;
						print $log_fh "md5: $md5\n";
					} elsif($crnt_checksum =~ m/sha1/i) { 
						$run_sha1 = 1;
						#Calculate sha1 checksum
						$sha1 = `openssl sha1 $filepath`;
						$sha1 =~ s/^.*=\s//g;
						$sha1 =~ s/\s//g;
						print $log_fh "sha1: $sha1\n";
						
					} elsif($crnt_checksum =~ m/sha256/i) { 
						$run_sha256 = 1;
						#Calculate sha256 checksum
						$sha256 = `openssl sha256 $filepath`;
						$sha256 =~ s/^.*=\s//g;
						$sha256 =~ s/\s//g;
						$sha256 =~ s/\n//g;
						print $log_fh "sha256: $sha256\n";
					}
				}
				
				if($format =~ m/csv/) { 
					$csv_parent = 
						"\"".escape_quote($num_file)."\","
						."\"".escape_quote($source_id)."\","
						."\"".escape_quote($_)."\","
						."\"".escape_quote($crnt_file)."\","
						."\"".escape_quote($filesize)."\""
						.($run_md5 ? ",\"".escape_quote($md5)."\"" : "")
						.($run_sha1 ? ",\"".escape_quote($sha1)."\"" : "")
						.($run_sha256 ? ",\"".escape_quote($sha256)."\"" : "")
					."\n";
					print $csvfiles_fh $csv_parent;
				}
				if($format =~ m/tsv/) { 
					$tsv_parent = escape_quote($num_file)."\t"
						."\"".escape_quote($source_id)."\"\t"
						.escape_quote($_)."\t"
						.escape_quote($crnt_file)."\t"
						.escape_quote($filesize)
						.($run_md5 ? "\t".escape_quote($md5) : "")
						.($run_sha1 ? "\t".escape_quote($sha1) : "")
						.($run_sha256 ? "\t".escape_quote($sha256) : "")
					."\n";
					print $tsvfiles_fh $tsv_parent;
				}

				if($format =~ m/sql/) { 
					$sql_parent = "INSERT INTO files "
					."(`id`, `source_id`, `file`, `filename`, `filesize`"
						.($run_md5 ? ", `md5_checksum`" : "")
						.($run_sha1 ? ", `sha1_checksum`": "")
						.($run_sha256 ? ", `sha256_checksum`" : "")
						.") "
					."VALUES "
					."("
						."\"".escape_quote($num_file)."\","
						."\"".escape_quote($source_id)."\","
						."\"".escape_quote($_)."\","
						."\"".escape_quote($crnt_file)."\","
						."\"".escape_quote($filesize)."\""
						.($run_md5 ? ",\"".escape_quote($md5)."\"" : "")
						.($run_sha1 ? ",\"".escape_quote($sha1)."\"" : "")
						.($run_sha256 ? ",\"".escape_quote($sha256)."\"" : "")
					.");\n";
					print $sql_fh $sql_parent;
				}

				if($verbose > 1) { print $sql_parent; }
				my $raw_exif = `exiftool -P -t $filepath`;
				my @lines = split(/\n/, $raw_exif);
				foreach my $line (@lines) { 
					my $key = $line;
					$key =~ s/\t.*$//g;
					$key =~ s/\s//g;
					my $val = $line;
					$val =~ s/^.*\t//g;
					if(exists($ignore_params{$key}) || !length($val)) { 
						print $log_fh "Ignore: $key => $val\n";
					} else {
						print $log_fh $key.":".$val."\n";
						if($format =~ m/csv/) { 
							$csvmeta_child = "\"".escape_quote($num_file)."\","
								."\"".escape_quote($key)."\","
								."\"".escape_quote($val)."\"\n";
							print $csvmeta_fh $csvmeta_child;
						}
						if($format =~ m/tsv/) { 
							$tsvmeta_child = escape_quote($num_file)."\t"
								.escape_quote($key)."\t"
								.escape_quote($val)."\n";
							print $tsvmeta_fh $tsvmeta_child;
						}
						if($format =~ m/sql/) { 
							$sql_child = "INSERT INTO `metadata` "
								."(`file_id`, `key`, `value`) VALUES "
								."(\"".escape_quote($num_file)."\",\"".escape_quote($key)."\",\"".escape_quote($val)."\");\n";
							print $sql_fh $sql_child;
						}
						if($verbose > 1) { print $sql_child; }
					}
				}
			}
		}
	}
}
sub verify_dirs {
	my ($offset, @args) = @_;
	my @ret; 
	#print "OFfset: $offset\n";
	for(my $i = $offset+1; $i < scalar(@args); $i++) { 
		my $crnt_dir = $args[$i];
		$crnt_dir =~ s/\/$//g;
		if($crnt_dir =~ m/^-/) {
			last;
		} else { 
			if(-d $crnt_dir) {
				#print "$crnt_dir\n";
				push @ret, $crnt_dir;
			} else { 
				my $err_msg = "\"".$crnt_dir."\" - is NOT a directory... Skipping\n"; 
				print $err_fh $err_msg; 
				print $err_msg; 
			}
		}
	}
	return @ret;
}
sub get_checksums { 
	my ($offset, @args) = @_;
	my @ret; 
	my %possible_checksums = map { $_ => 1 } @possible_checksums;
	for(my $i = $offset+1; $i < scalar(@args); $i++) { 
		my $checksum = $args[$i];
		if($checksum =~ m/^-/) { 
			last;
		} else {
			if(exists($possible_checksums{$checksum})) { 
				push @ret, $checksum;
			} else { print "\n\nArgument (Checksum) not recognized...\n\n\"$checksum\"\n\n"; exit; }
		}
	}
	if(scalar(@ret) > 0) { 
		return @ret;
	} else { return @possible_checksums; } 
}
sub AddSlashes {
	my $text = shift;
	## Make sure to do the backslash first!
	$text =~ s/\\/\\\\/g;
	$text =~ s/\ /\\\ /g;
	$text =~ s/\&/\\\&/g;
	$text =~ s/\(/\\\(/g;
	$text =~ s/\)/\\\)/g;
	$text =~ s/'/\\'/g;
	$text =~ s/"/\\"/g;
	$text =~ s/\\0/\\\\0/g;
	return $text;
}
sub escape_quote {
	my $text = shift;
	$text =~ s/\'/\\\'/g;
	$text =~ s/\"/\\\"/g;
	return $text;
}
sub getLoggingTime {
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
	my $nice_timestamp = sprintf ( "%04d%02d%02d_%02d%02d%02d",$year+1900,$mon+1,$mday,$hour,$min,$sec);
	return $nice_timestamp;
}
