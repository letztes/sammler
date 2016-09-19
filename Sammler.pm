=pod

=head2 faq

Q Perl module xyz is missing
A Make sure the following are installed on a ubuntu machine:
libmoosex-declare-perl libnet-pcap-perl libnetpacket-perl libxml-libxml-perl

=cut

package Sammler;
  
use strict;
use warnings;

use feature 'say';

use Data::Dumper;
use File::Path qw(make_path);
use MooseX::Declare;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use URI::Escape;
use XML::LibXML;

class Sammler {
    
    has 'device' => (
        isa      => 'Str',
        is       => 'rw',
        builder  => '_get_device',
        required => 1,
    );
    
    has 'sniffer' => (
        isa      => 'Object',
        is       => 'rw',
        builder  => 'open_sniffer',
        required => 1,
    );
    
    has 'inventories_directory' => (
        isa      => 'Str',
        is       => 'rw',
        default  => $ENV{'HOME'}.'/code/sammler/inventories/',
        required => 1,
    );
    
    has 'dom_of' => (
        isa      => 'HashRef',
        is       => 'rw',
        builder  => '_read_inventories',
        required => 1,
    );
    
    has 'answer_for' => (
        isa      => 'HashRef',
        is       => 'rw',
        default  => sub {{}},
        
        # Cannot be built automatically, for it depends on $self->dom_of
        # Build it manually in the run method
    );
    
    method _get_device {
        
        my ($net, $mask, $err);
        my @devices = Net::Pcap::findalldevs(\$err);
        
        # Net::Pcap::lookupdev() is told to return
        # the first suitable device, but the first one is
        # not always the active one.
        # Net::Pcap::lookupnet() returns the active one.
        foreach my $device (@devices) {
            Net::Pcap::lookupnet($device, \$net, \$mask, \$err);
            return $device if $net;
        }
        
        say $err if $err;
        
        # The method returns on success few lines above.
        # The method must not reach this point.
        say 'No device found. Are you root?';
        exit;
    }
    
    method _read_inventories {
        
        my %dom_of; # DOM of each inventory.
        my $number_of_questions_in_all_inventories = 0;
        
        # Because this method is used for building an attribute
        # it is not possible to use another attributes here.
        # This is the reason for redundancy of 
        # $self->{'inventories_directory'};
        my $inventories_directory = $ENV{'HOME'}.'/code/sammler/inventories/';

        # Because the category "Computer/EDV" contains a slash in the name
        make_path($inventories_directory.'Computer');
            
        opendir(INVENTORIES, $inventories_directory) or die $!;
        my @inventories = readdir(INVENTORIES) or die $!;
        closedir(INVENTORIES);

        my $parser = XML::LibXML->new();
        
        # Because the category "Computer/EDV" contains a slash in the name,
        # EDV is treated as a subdirectory
        foreach my $inventory (@inventories, 'Computer/EDV.xml') {
            
            # Skip 'Computer'. It's a subdirectory.
            next if not -f $inventories_directory.$inventory;
            next if $inventory !~ m/^(.+)\.xml$/;
                
            my $category_name = uri_unescape($1);
            
            $dom_of{$category_name} =
              $parser->parse_file($inventories_directory.$inventory)
               or die $!;
              
            $dom_of{$category_name}->setEncoding('UTF-8');
            
            my $root_node = $dom_of{$category_name}->documentElement();
            
            my @items = $root_node->findnodes('//item');
            
            $number_of_questions_in_all_inventories +=
              scalar(@items);
        }
            
        print "\nNumber of questions already gathered: ";
        print "$number_of_questions_in_all_inventories\n\n";
        
        return \%dom_of;
    }
    
    method write_to_file (HashRef $args) {

        my $category_to_write = $args->{'category'};
        my $question_to_write = $args->{'question'};
        my $answer_to_write   = $args->{'answer'};
        
        $category_to_write =~ s/\n//g;
        $question_to_write =~ s/\n//g;
        $answer_to_write =~ s/\n//g;
        
        $question_to_write = uri_escape( $question_to_write );
        $answer_to_write   = uri_escape( $answer_to_write );
        
        my $new_item_node = XML::LibXML::Element->new('item');

        my $new_question_node = XML::LibXML::Element->new('question');
        $new_question_node->appendText($question_to_write);

        my $new_answer_node = XML::LibXML::Element->new('answer');
        $new_answer_node->appendText($answer_to_write);

        $new_item_node->appendChild($new_question_node);
        $new_item_node->appendChild($new_answer_node);
        
        my $root_node = $self->dom_of->{$category_to_write}->documentElement();
        $root_node->appendChild($new_item_node);

        print "category: $category_to_write\n";
        $self->dom_of->{$category_to_write}->toFile($self->inventories_directory.
        "$category_to_write.xml",) or die $!;
        
        return;
    }
    
    method make_new_dom {
        
        my $dom = XML::LibXML->createDocument("1.0", "UTF-8");
        $dom->setEncoding('UTF-8');
        
        my $root_node = XML::LibXML::Element->new('inventory');
        $dom->setDocumentElement( $root_node );
        
        return $dom;
    }
    
    method open_sniffer {
        
        my $snaplen    = 1500;
        my $promisc    = 0;
        my $timeout_ms = 0;
        my $err;
        
        my $ip;
        my $netmask;
        Net::Pcap::lookupnet($self->device, \$ip, \$netmask, \$err,);
        if (defined $err) {
            die 'Unable to look up device information for ', $self->device, ' - ', $err;
        }
                             
        my $sniffer 
            = Net::Pcap::open_live($self->device, $snaplen, $promisc, $timeout_ms, \$err);

        if (defined $err) {
            die 'Unable to open live device for ', $self->device, ' - ', $err;
        }
        
        my $filter;
        Net::Pcap::compile($sniffer, \$filter,
            'host 2001:780:138:481::d55f:4f5d',
            0, #do not optimize
            $netmask);

        # Returns something that is not equal zero on error
        my $error_status = Net::Pcap::setfilter($sniffer, $filter);
        if ($error_status) {
            die 'Unable to set packet capture filter. Error status: ' . $error_status;
        }
        
        return $sniffer;
    }
    
    method extract_question (Str $netpacket) {
        
        if ($netpacket =~ m/Quiz(?:\d| 50\+)?#QuizBot\d?#..#a#.FRAGE. (.+) \(Kategorie: (.+),/i) {
            
            my $question = $1;
            my $category = $2;
            
            return($question, $category);
        }
        
        return;
    }
    
    method extract_answer (Str $netpacket) {
        
        if ($netpacket =~ m/(Quiz(?:\d|\ 50\+)?).+(?:Antwort lautet|ist richtig)/) {
        
            my $answer = $netpacket;
            
            # remove the unnecessary leading and latter part of the
            $answer =~ s/^.+Quiz(?:\d|\ 50\+)?#QuizBot(?:\d|\ 50\+)?#..#a#//msg;
            $answer =~ s/^Die Antwort lautet: //msg;
            $answer =~ s#(?: ist richtig|</p>|&lt;/p&gt;|\n).*$##msg;
            
            return $answer;
        }
        
        return;
    }
    
    method lookup_answer (HashRef $args) {

        my $question = $args->{'question'};
        my $category = $args->{'category'};
    
        if ($category eq 'Rechenaufgabe'
        and $question =~ m!^[\^\(\)\d\+\-\*\/\=\?\. ]+$!) {
            $question =~ s/ =.+$//;
            $question =~ s/\^/\*\*/g;
            
             # eval strings from the internet with root privileges?
             # Yes, we can!
            my $answer = eval($question);
            
            if ($question =~ m/^\d\d?(?:\*\*\d)? [+\-*] \d\d?(?:\*\*\d)? [+\-*] \d\d?(?:\*\*\d)? [+\-*] \d\d?(?:\*\*\d)? [+\-*] \d\d?(?:\*\*\d)?(?: [+\-*] \d\d?(?:\*\*\d)?)?$/) {
                print "sleep 2 seconds now because question seems hard\n";
                sleep 2;
            }
            
            # Say answer here instead of returning it because otherwise
            # the risk of inventorizing it would be greater.
            say $answer;
            
            return;
        }
        else {
            if (my $answer = $self->answer_for->{ $question }) {
                return $answer;
            }
        }
        
        if (not exists $self->dom_of->{$category}) {
            $self->dom_of->{$category} = make_new_dom();
        }
            
        return;
    }
    
    
    # Build one large hash of answers for questions regardless the
    # category.
    
    method build_answer_for {
        
        foreach my $dom (values %{ $self->dom_of }) {
            foreach my $item_node ($dom->findnodes('//item')) {
                
                my $question = uri_unescape($item_node->findvalue('question'));
                my $answer = uri_unescape($item_node->findvalue('answer'));
                
                $self->answer_for->{ $question } = $answer;
            }
        }
        
        return;
    }
    
    method run {
        
        # Read the dom of known question-answer pairs initially
        # and build the hashref for looking up answers for questions
        $self->build_answer_for();
        
        # Needed by libpcap. Of no practical use here.
        my %header;
        
        # Variables known in whole method.
        # On extracting the answer it is known whether the answer
        # belongs to a question.
        my $previous_question = '';
        my $question;
        my $category;
        my $answer;
        
        while (1) {
            PACKET: while (my $packet = Net::Pcap::next($self->sniffer, \%header)) {
            
                my $ether_data = NetPacket::Ethernet::strip($packet);
                my $ip_data = NetPacket::IP::strip($ether_data);
                
                my $tcp_obj = NetPacket::TCP->decode($ip_data);
                my $content = $tcp_obj->{'data'};
                
                $content = uri_unescape($content);
                
                # Process only messages from QuizBot
                next if not $content =~ m/Quiz(?:\d| 50\+)?#QuizBot/ms;
                
                if (my ($next_question, $next_category) = $self->extract_question($content)) {
                    
                    # sometimes the same netpacket is read twice
                    next PACKET if $next_question eq $previous_question;
                    $previous_question = $next_question;
                    
                    # Set the variables that get evaluated in the part
                    # where the answer is extracted
                    $question = $next_question;
                    $category = $next_category;
                    
                    if (my $inventorized_answer = $self->lookup_answer({
                            'question' => $question,
                            'category' => $category,
                        })) {
                    
                        say $inventorized_answer;
                        
                        # No need to inventorize them again.
                        $question = undef;
                        $category = undef;
                    }
                    
                    next PACKET;
                }
                
                if ($answer = $self->extract_answer($content)) {
                    
                    # Write to file only complete question-answer
                    # pairs.
                    if ($question
                    and $category
                    and $answer
                    and $category ne 'Rechenaufgabe') {
                        $self->write_to_file({
                            'question' => $question,
                            'category' => $category,
                            'answer'   => $answer,
                        });
                        
                        $self->answer_for->{ $question } = $answer;
                    }
                }
                    
            }
        }
        
        return;
    }
}










1;
