#!/usr/bin/perl
  
use strict;
use warnings;

use feature 'say';

use Data::Dumper;
use Getopt::Long qw(:config bundling);

use Sammler;

my $sammler = Sammler->new();



$sammler->run();



