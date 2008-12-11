#! /usr/bin/perl -w

#################################################################
# create_help.pl -- converts SGML docs to internal psql help
#
# Copyright (c) 2000-2008, PostgreSQL Global Development Group
#
# $PostgreSQL: pgsql/src/bin/psql/create_help.pl,v 1.18 2008/11/19 09:51:55 petere Exp $
#################################################################

#
# This script automatically generates the help on SQL in psql from
# the SGML docs. So far the format of the docs was consistent
# enough that this worked, but this here is by no means an SGML
# parser.
#
# Call: perl create_help.pl docdir sql_help.h
# The name of the header file doesn't matter to this script, but it
# sure does matter to the rest of the source.
#

use strict;

my $docdir = $ARGV[0] or die "$0: missing required argument: docdir\n";
my $outputfile = $ARGV[1] or die "$0: missing required argument: output file\n";

my $outputfilebasename;
if ($outputfile =~ m!.*/([^/]+)$!) {
    $outputfilebasename = $1;
}
else {
    $outputfilebasename = $outputfile;
}

my $define = $outputfilebasename;
$define =~ tr/a-z/A-Z/;
$define =~ s/\W/_/g;

opendir(DIR, $docdir)
    or die "$0: could not open documentation source dir '$docdir': $!\n";
open(OUT, ">$outputfile")
    or die "$0: could not open output file '$outputfile': $!\n";

print OUT
"/*
 * *** Do not change this file by hand. It is automatically
 * *** generated from the DocBook documentation.
 *
 * generated by
 *     $^X $0 @ARGV
 *
 */

#ifndef $define
#define $define

#define N_(x) (x)				/* gettext noop */

struct _helpStruct
{
	const char	   *cmd;		/* the command name */
	const char	   *help;		/* the help associated with it */
	const char	   *syntax;		/* the syntax associated with it */
};


static const struct _helpStruct QL_HELP[] = {
";

my $maxlen = 0;

my %entries;

foreach my $file (sort readdir DIR) {
    my (@cmdnames, $cmddesc, $cmdsynopsis);
    $file =~ /\.sgml$/ or next;

    open(FILE, "$docdir/$file") or next;
    my $filecontent = join('', <FILE>);
    close FILE;

    # Ignore files that are not for SQL language statements
    $filecontent =~ m!<refmiscinfo>\s*SQL - Language Statements\s*</refmiscinfo>!i
	or next;

    # Collect multiple refnames
    LOOP: { $filecontent =~ m!\G.*?<refname>\s*([a-z ]+?)\s*</refname>!cgis and push @cmdnames, $1 and redo LOOP; }
    $filecontent =~ m!<refpurpose>\s*(.+?)\s*</refpurpose>!is and $cmddesc = $1;
    $filecontent =~ m!<synopsis>\s*(.+?)\s*</synopsis>!is and $cmdsynopsis = $1;

    if (@cmdnames && $cmddesc && $cmdsynopsis) {
        s/\"/\\"/g foreach @cmdnames;

	$cmddesc =~ s/<[^>]+>//g;
	$cmddesc =~ s/\s+/ /g;
        $cmddesc =~ s/\"/\\"/g;

	$cmdsynopsis =~ s/<[^>]+>//g;
	$cmdsynopsis =~ s/\r?\n/\\n/g;
        $cmdsynopsis =~ s/\"/\\"/g;

        foreach my $cmdname (@cmdnames) {
	    $entries{$cmdname} = { cmddesc => $cmddesc, cmdsynopsis => $cmdsynopsis };
	    $maxlen = ($maxlen >= length $cmdname) ? $maxlen : length $cmdname;
	}
    }
    else {
	die "$0: parsing file '$file' failed (N='@cmdnames' D='$cmddesc')\n";
    }
}

print OUT "    { \"$_\",\n      N_(\"".$entries{$_}{cmddesc}."\"),\n      N_(\"".$entries{$_}{cmdsynopsis}."\") },\n\n" foreach (sort keys %entries);

print OUT "
    { NULL, NULL, NULL }    /* End of list marker */
};


#define QL_HELP_COUNT	".scalar(keys %entries)."		/* number of help items */
#define QL_MAX_CMD_LEN	$maxlen		/* largest strlen(cmd) */


#endif /* $define */
";

close OUT;
closedir DIR;
