#!/usr/bin/perl -w

use Time::HiRes qw/ time sleep /;

my $start = time;
system("john --format=crypt $ARGV[0]");
my $end = time;
my $run_time = $end - $start;
print "Elapsed time: $run_time\n";
