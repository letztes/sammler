use strict;
use warnings;
use XML::LibXML;
#use Time::HiRes qw(gettimeofday);

my $directory = "inventories/";

opendir(INVENTORIES, $directory);
my @inventories = readdir(INVENTORIES);
closedir(INVENTORIES);

my $parser = XML::LibXML->new();
foreach(@inventories) {
  if ($_ =~ m/xml$/) {
    print "now checking: $_\n";
    my $dom = $parser->parse_file($directory.$_);
    my $root = $dom->documentElement();
    my @questions = $dom->findnodes('//question');
    while (my $question1 = shift @questions) {
      foreach my $question2 (@questions) {
        if ($question1->to_literal eq $question2->to_literal) {
          print "\n$_\n";
          print $question2->to_literal;
          print "\n";
          my $item_node = $question2->parentNode;
          $item_node->unbindNode();
          $dom->toFile($directory.$_) or die $!;
        }
      }
    }
  }
}
