#!/usr/bin/perl

=head2

Reformats the urlencoding of the inventory in case they change it.
Overwrites the original files. Does not automatically any backups.
Make backups on your own. Examine the network. Write good regexes.

=cut

use strict;
use warnings;

use URI::Escape;
use XML::LibXML;

my $DIRFH;
my $READFH;
my $WRITEFH;

my $INVENTORIES_DIRECTORY = $ENV{'HOME'}.'/code/sammler/inventories/';
#my $INVENTORIES_DIRECTORY = $ENV{'HOME'}.'/code/sammler/test_inventory/';

my $parser = new XML::LibXML;

opendir($DIRFH, $INVENTORIES_DIRECTORY) or die $!;
my @INVENTORIES = grep { m/xml$/ } sort readdir($DIRFH) or die $!;
closedir($DIRFH);
my $last = $#INVENTORIES + 1;
my $i = 0;
foreach my $inventory (@INVENTORIES) {
    $i++;
    print "processing ( $i / $last ) $inventory\n";
        
    my $new_dom = XML::LibXML->createDocument("1.0", "UTF-8");
    #$new_dom->setEncoding('UTF-8');
    my $root_element = XML::LibXML::Element->new('inventory');
    $new_dom->setDocumentElement($root_element);
    $root_element = $new_dom->documentElement();
    
    my $dom = $parser->parse_file($INVENTORIES_DIRECTORY.$inventory);
    
    foreach my $item ($dom->findnodes('//item')) {
        my $question = $item->findvalue('question');
        my $answer = $item->findvalue('answer');
        
        $question = uri_escape(uri_unescape($question));
        $answer   = uri_escape(uri_unescape($answer));
        
        my $new_item_node = XML::LibXML::Element->new('item');
        $root_element->appendChild($new_item_node);

        my $new_question_node = XML::LibXML::Element->new('question');
        $new_question_node->appendText($question);

        my $new_answer_node = XML::LibXML::Element->new('answer');
        $new_answer_node->appendText($answer);

        $new_item_node->appendChild($new_question_node);
        $new_item_node->appendChild($new_answer_node);

        $new_dom->toFile($INVENTORIES_DIRECTORY.$inventory) or die $!;
        
    }
}
