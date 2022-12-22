#! /usr/bin/perl
$INPUT=`cat -`;

$INPUT =~ tr/a-z/A-Z/;
print $INPUT;
