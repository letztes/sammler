#!/usr/bin/perl

# TODO:
#       * usage_message according to pod2usage. Compare
#         http://search.cpan.org/~jv/Getopt-Long-2.38/lib/Getopt/Long.pm#Documentation_and_help_texts
#         and
#         http://search.cpan.org/~marekr/Pod-Parser-1.38/lib/Pod/Usage.pm
#
#       * full automatic log in etc.
#       * automatic join into quizchannel in case of eventual leaving.
#       * variable, randomly selected standard messages like
#         'mach hin bot'


# Fragen erst uri_unescaped dann explizit erneut uri_escaped speichern.
# Klartext ist nicht geeignet, weil XML-Entitys dann hin und her kodiert
# werden müssen und die Zeichenkodierung durcheinander kommen koennte

  
use strict;
use warnings;

use feature 'say';

use Data::Dumper;
use Getopt::Long qw(:config bundling);
use HTTP::Request::Common;
use LWP;
use Pod::Usage;
use Time::HiRes qw(gettimeofday);
use URI::Escape;
use XML::LibXML;

##########
# Global variables that control the behaviour of this script.
##########

my $DEVICE = 'wlan0';

my $last_time_of_looking_up_answer;

my $java_mode;

# Substring from user agent string. Used for killing the browser
# in case of chat command 'quit';
my $browser;

# Sends the answer automatically to the quizroom if turned on. Else
# prints the answer to tty.
my $active_mode = 0;

# Sends the answer automatically to the quizroom in random
# intervalls if turned on.
my $gathering_mode = 0;
my $interval = 1200;
my $interval_minimum = 1200; # 1200 = 60 sec * 20 min.
my $interval_maximum = 1800; # 1800 = 60 sec * 30 min.

# If turned on, some character combinations will be converted to
# umlauts for no other reason but silliness.
my $funny_mode = 0;

# If turned on, some adjucent characters will get swapped and
# afterward the correct answer will be printed.
my $camouflage_mode = 0;

# Time in seconds between looking up the correct answer and and
# printing it out. This default value shall be controlled dynamically
# via chatmessages.
# BTW: Another fast user made 24 characters in 6 seconds (including
# reading the question and thinking). That's 0.25 seconds
# per character.
# 0.5 seems to be a good value in combination with
# delay_per_character=0.2.
my $delay = 1;
my $delay_per_character = 0.2;

# in case the answer shall be in lower case.
my $lower_case = 0;

# min and max seconds to wait before sending the idle preventing message
my $interval_values;

# The above declared global variables can additionaly be assigned via
# the commandline params as follows.

GetOptions ("active|a" => \$active_mode,
            "camouflage|c" => \$camouflage_mode,
            "delay|d=f" => \$delay,
            "funny|f" => \$funny_mode,
            "gathering|g" => \$gathering_mode,
            "interval|i=s" => \$interval_values,
            "lowercase|l" => \$lower_case,
            "delay_per_character|typing|typer|type|t=f"
            => \$delay_per_character,
            );

# While gathering lower case shall be the default.
if ($gathering_mode) {$lower_case = 1;}
# Check interval values.
if ($interval_values) {
    ($interval_minimum, $interval_maximum) = split(/,/,$interval_values)
    or &usage();
    if ($interval_minimum < 60 or $interval_minimum > 1800) {&usage();}
    if ($interval_maximum < 60 or $interval_maximum > 1800) {&usage();}
    if ($interval_maximum - $interval_minimum < 0) {&usage();}
}

# Active mode and gahtering mode must not be chosen at the same time.
if ($active_mode) {$gathering_mode = 0;}

my $room;
my ($seconds, $useconds) = gettimeofday();
my $last_time_of_sending = $seconds;

##########
# Global variables concerning the http header. Some of them are
# assigned dynamically while sniffing the nettraffic. The ones
# hardcoded here are for the case surfing in other sites at the same
# time, so the header information won't interfere. (Which is not very
# probably, since only the data sent to spin.de hosts is sniffed)
##########

my $get;
my $host = 'html.www.spin.de';
my $user_agent;
my $accept_mimetype = 
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
my $accept_language = 'de-de,de;q=0.8,en-us;q=0.5,en;q=0.3';
my $accept_encoding = 'gzip,deflate';
my $accept_charset = 'ISO-8859-1,utf-8;q=0.7,*;q=0.7';
my $keep_alive = '300';
my $connection = 'keep-alive';
my $referer;
my $cookie;
my $session;

my $request;
my $response;

my $useragent = LWP::UserAgent->new;

##########
# Global variables concerning the quizroom, the category, the question
# and the answer of the quizgame.
##########

my $number_of_questions_in_inventory = 0;
my $number_of_questions_in_current_category;
my @items;

my $inventories_directory = $ENV{'HOME'}.'/code/sammler/inventories/';
#my $inventories_directory = 'inventories/';

my %DOM_OF; # DOM of each inventory.
my %root_of;
my %old_items_of;

if (not -e $ENV{'HOME'}.
  '/code/sammler/inventories/Computer/EDV.xml') {
    if (not -e $ENV{'HOME'}.'/code/sammler/inventories/Computer/') {
        if (not -e $ENV{'HOME'}.'/code/sammler/inventories/') {
            if (not -e $ENV{'HOME'}.'/code/sammler/') {
                mkdir $ENV{'HOME'}.'/code/sammler/';
            }
            mkdir $ENV{'HOME'}.'/code/sammler/inventories/';
        }
        mkdir $ENV{'HOME'}.'/code/sammler/inventories/Computer/';
    }
    &make_new_dom('Computer/EDV');
    $DOM_OF{'Computer/EDV'}->toFile($ENV{'HOME'}.
      '/code/sammler/inventories/Computer/EDV.xml');
}
opendir(INVENTORIES, $inventories_directory) or die $!;
my @inventories = readdir(INVENTORIES) or die $!;
closedir(INVENTORIES);

my $parser = XML::LibXML->new();
foreach my $inventory (@inventories) {
    if ($inventory =~ m/^(.+)\.xml$/) {
        my $category_name = uri_unescape($1);
        $DOM_OF{($category_name)} =
          $parser->parse_file($inventories_directory.$inventory) or die $!;
        $DOM_OF{($category_name)}->setEncoding('UTF-8');
        $root_of{($category_name)} =
          $DOM_OF{($category_name)}->documentElement();
        @items = $root_of{($category_name)}->findnodes('//item');
        $number_of_questions_in_current_category = @items;
        $number_of_questions_in_inventory +=
          $number_of_questions_in_current_category;
    }
}

# Because the category "Computer/EDV" contains a slash in the name,
# the block again for the explicit subdirectory.
{
    my $inventory = 'Computer/EDV.xml';
    my $category_name = 'Computer/EDV';
    $DOM_OF{($category_name)}
    = $parser->parse_file($inventories_directory.$inventory) or die $!;
    $DOM_OF{($category_name)}->setEncoding('UTF-8');
    $root_of{($category_name)} = $DOM_OF{($category_name)}->documentElement();
    @items = $root_of{($category_name)}->findnodes('//item');
    $number_of_questions_in_current_category = @items;
    $number_of_questions_in_inventory
    += $number_of_questions_in_current_category;
}
    
print "\nNumber of questions already gathered: ";
print "$number_of_questions_in_inventory\n\n";

#######
# Subroutines
#######


sub usage {
print << "END_USAGE_MESSAGE";
Usage: sammler [options]
Options are:
         -a, --active            Send answers automatically into chatroom
         -c, --camouflage        Put random typos into the answer;
                                 send the correct answer within the very
                                 next 2 seconds.
         -d, --delay SECONDS     While in active or gathering mode wait
                                 SECONDS seconds before sending answer.
                                 Default value for delay is 1 second.
         -f, --funny             Replace some character combinations that are
                                 accepted by QuizBot, i.e. ae to a-umlaut.
         -g, --gathering         Avoid idle-kick. Send answer after a certain
                                 interval of time passed. Interval can be set
                                 with the -i parameter (default is a random
                                 generated value between 1200 and 1800). After
                                 SECONDS seconds have passed, answer one
                                 single question and be quiet again.
         -i, --interval SECONDS,SECONDS
                                 While in gathering mode, remains passively
                                 for a certain interval.
                                 Interval is random generated after each
                                 sending. Interval is set by default with
                                 the values 1200 seconds for interval
                                 minimum and 1800 seconds for interval
                                 maximum.
                                 If a static interval of e.g. 1 minute
                                 is desired, the correct parameter would
                                 be
                                    -i 60,60
                                 Valid values for interval minimum and
                                 interval maximum are between 60 and
                                 1800.
                                 The values of interval minimum and interval
                                 maximum are only valid if the value of
                                 interval minimum is lower than or equal
                                 the value of interval minimum.
         -l, --lowercase         Send everything in lower case only.
         -t, --type, --typer, --typing, --delay_per_character SECONDS
                                 While in active or gathering mode wait
                                 SECONDS seconds multiplied with number of
                                 characters in answer string before sending
                                 answer.
                                 Default value for delay_per_character
                                 is 0.2 seconds.
END_USAGE_MESSAGE

  exit;
}


sub write_to_file {

    my $category_to_write = shift;
    my $question_to_write = shift;
    my $answer_to_write = shift;
    
    $category_to_write =~ s/\n//g;
    $question_to_write =~ s/\n//g;
    $answer_to_write =~ s/\n//g;
    
    my $new_item_node = XML::LibXML::Element->new('item');
    $root_of{$category_to_write}->appendChild($new_item_node);

    my $new_question_node = XML::LibXML::Element->new('question');
    $new_question_node->appendText($question_to_write);

    my $new_answer_node = XML::LibXML::Element->new('answer');
    $new_answer_node->appendText($answer_to_write);

    $new_item_node->appendChild($new_question_node);
    $new_item_node->appendChild($new_answer_node);

    print "category: $category_to_write\n";
    $DOM_OF{$category_to_write}->toFile($inventories_directory.
    "$category_to_write.xml",) or die $!;

}

# Converts some character combinations to umlauts for no other reason
# but silliness.

sub make_look_funny {
    my $string = shift;
    
# Converts 'ae' (and 'a' in the last place) to 'ä' %c3%a4;
    $string =~ s/ae/\%c3\%a4/g;
    $string =~ s/a$/\%c3\%a4/;
    
# 'oe'/'o' => 'ö' %c3%b6.
    $string =~ s/oe/\%c3\%b6/g;
    $string =~ s/oe$/\%c3\%b6/;
    
# 'ue'/'u' => 'ü' %c3%bc;
    $string =~ s/ue/\%c3\%bc/g;
    $string =~ s/ue$/\%c3\%bc/;
    
# 'ss'/'s' => 'ß' %c3%9f;
    $string =~ s/ss/\%c3%9f/g;
    $string =~ s/s$/\%c3%9f/;
    
    return($string);
}

=head2

The http stuff has changed. Its post now.


..1...\7,......'._O+.c.P.#..
...RR3.?POST /in HTTP/1.1
Host: html.www.spin.de
User-Agent: Mozilla/5.0 (X11; U; Linux i686; de; rv:1.9.2.18) Gecko/20110628 Ubuntu/10.10 (maverick) Firefox/3.6.18
Accept-Encoding: gzip,deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 115
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: http://html.www.spin.de/conn?sid=p6HFgatmes3qzXRttU41AQvIpNHXSx4BGlXyXzj3st6g6713057&port=3003&ign=1311017310740
Content-Length: 118
Cookie: loginid=3PlJAnKx4BG3pyXzj3st6g; __utma=1.132348816.1311016405.1311016405.1311016405.1; __utmc=1; __utmz=1.1311016405.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); settings=0000010000; session1=p6HFgatmes3qzXRttU41AQvIpNHXSx4BGlXyXzj3st6g6713057; session2=p6HFgatmes3qzXRttU41AQvIpNHXSx4BGlXyXzj3st6g6713057; design=0-0; setup=vhost=spin.de&url=%2Fhome
Pragma: no-cache
Cache-Control: no-cache

sid=p6HFgatmes3qzXRttU41AQvIpNHXSx4BGlXyXzj3st6g6713057&port=3003&msg=gQuiz%23a%23Urknall%0A&snd=271&ign=1311023709742




=cut

sub extract_http_values {
    my $netpacket = shift;
    if ($netpacket =~ m!GET (/in.+&port.+&msg.+&snd.+)!) {
        $get = $1;
        $get =~ s/^\s//;
        $get =~ s/\s$//;
        $get =~ s! HTTP/1.1!!;
    }
    if ($netpacket =~ m!^Host: (.+)!) {
        $host = $1;
        $host =~ s/^\s//;
        $host =~ s/\s$//;
    }
    if ($netpacket =~ m!^User-Agent: (.+)!) {
        $user_agent = $1;
        $user_agent =~ s/^\s//;
        $user_agent =~ s/\s$//;
        if ($user_agent =~ m/Firefox/) {
            $browser = 'firefox';
        }
# Attention: Epiphany also has the substring 'Firefox' in its
# user agent string.
        if ($user_agent =~ m/Epiphany/) {
            $browser = 'epiphany-browser';
        }
        if ($user_agent =~ m/Opera/) {
            $browser = 'opera';
        }
    }
    if ($netpacket =~ m!^Accept: (.+)!) {
        $accept_mimetype = $1;
        $accept_mimetype =~ s/^\s//;
        $accept_mimetype =~ s/\s$//;
    }
    if ($netpacket =~ m!^Accept-Language: (.+)!) {
        $accept_language = $1;
        $accept_language =~ s/^\s//;
        $accept_language =~ s/\s$//;
    }
    if ($netpacket =~ m!^Accept-Encoding: (.+)!) {
        $accept_encoding = $1;
        $accept_encoding =~ s/^\s//;
        $accept_encoding =~ s/\s$//;
    }
    if ($netpacket =~ m!^Accept-Charset: (.+)!) {
        $accept_charset = $1;
        $accept_charset =~ s/^\s//;
        $accept_charset =~ s/\s$//;
    }
    if ($netpacket =~ m!^Keep-Alive: (.+)!) {
        $keep_alive = $1;
        $keep_alive =~ s/^\s//;
        $keep_alive =~ s/\s$//;
    }
    if ($netpacket =~ m!^Connection: (.+)!) {
        $connection = $1;
        $connection =~ s/^\s//;
        $connection =~ s/\s$//;
    }
    if ($netpacket =~ m!^Referer: (.+)!) {
        $referer = $1;
        $referer =~ s/^\s//;
        $referer =~ s/\s$//;
    }
    if ($netpacket =~ m!^Cookie: (.+)!) {
        $cookie = $1;
        $cookie =~ s/^\s//;
        $cookie =~ s/\s$//;
        
# extract session value for logging out later.
# currently the value of session1 is assigned to $session, i don't
# know what the difference between session1 and session2 is.
# in the tests i made so far their values have been identical.
        $cookie =~ /session1=(.+?);/;
        $session = $1;
    }
#  print "$netpacket\n";
    if ($netpacket =~ m!gQuiz(?:\d|\%2050\%2B)?#QuizBot(?:\d|\%2050\%2B)?#\d\d#a#!) {
        $java_mode = 1;
#        die "
#        Fatal error:
#        Non-ASCII-characters can not be captured while Java enabled.
#        Disable Java in browser settings, restart browser and try again.
#        ";
        if ($active_mode) {
            warn "
            Active mode not possible while connection established with Java
            applet.
            Disable Java in browser settings first.
            ";
            $active_mode = 0;
        }
    }
}


sub look_up_answer {
    my $netpacket = shift;
    my $category = shift;
    my $question = shift;
    my $answer;
    
    if ($category eq 'Rechenaufgabe'
    and uri_unescape($question) =~ m!^[\^\(\)\d\+\-\*\/\=\?\. ]+$!) {
        $question = uri_unescape($question);
        $question =~ s/ =.+$//;
        $question =~ s/\^/\*\*/g;
        $answer = eval($question); # eval strings from the internet with root privileges?
        print "\n\n";
        print $question;
        print "\n\n";
        if ($question =~ m/^\d\d?(?:\*\*\d)? [+\-*] \d\d?(?:\*\*\d)? [+\-*] \d\d?(?:\*\*\d)? [+\-*] \d\d?(?:\*\*\d)? [+\-*] \d\d?(?:\*\*\d)?(?: [+\-*] \d\d?(?:\*\*\d)?)?$/) {
            print "sleep 2 seconds now because question seems hard\n";
            sleep 2;
        }
        print $answer;
        print "\n";
        return($answer);
    }
    else {
        if (not exists $DOM_OF{$category}) {
            &make_new_dom($category);
        }
        $old_items_of{$category} =
          [$DOM_OF{$category}->findnodes('//item')];
        foreach(@{$old_items_of{$category}}) {
            if (lc($_->findvalue('question')) eq lc($question)) {
                $answer = $_->findvalue('answer');
                if ($answer =~ m/#(.+)#/) {$answer = $1;}
                print uri_unescape($answer);
                print "\n";
                # Delete the latter part of the answer string if it contains
                # parens because the parens data is in most cases needless.
                if ($answer =~ m/%20%28.+%29.*/) {
                    $answer =~ s/%20%28.+//;
                    print "\ntruncated parens:\n";
                    print uri_unescape($answer);
                    print "\n";
                }
                return($answer);
            }
        }
    }
    return undef;
}


sub make_new_dom {
    my $category = shift;
    $DOM_OF{$category} = XML::LibXML->createDocument("1.0", "UTF-8");
    $DOM_OF{($category)}->setEncoding('UTF-8');
    $root_of{$category} = XML::LibXML::Element->new('inventory');
    $DOM_OF{($category)}->setDocumentElement( $root_of{$category} );
    $root_of{$category} = $DOM_OF{$category}->documentElement();
}


sub extract_question {
    my $netpacket = shift;
    
    if ($netpacket =~ m/Quiz(?:\d|\%2050\%2B)?#QuizBot(?:\d|\%2050\%2B)?#..#a#%5BFRAGE%5D%20(.+)%20%28Kategorie:%20(.+)(?:,|%2C).+$/i) {
    
        my $question = $1;
        my $category = uri_unescape($2);
        return($question, $category);
    }
}


sub extract_answer {
    my $netpacket = shift;
    my $category = shift;
    my $question = shift;
    
    my $answer = $netpacket;
    # remove the unnecessary leading and latter part of the answerstring
    $answer =~ s/^.+Quiz(?:\d|\%2050\%2B)?#QuizBot(?:\d|\%2050\%2B)?#..#a#//g;
    $answer =~ s/^Die%20Antwort%20lautet(?:%3A|:)%20//g;
    $answer =~ s/(?:%20ist%20richtig|<\/p>|&lt;\/p&gt;).*$//g;
    &write_to_file($category, $question, $answer);
    return undef;
}


sub plus_one_or_minus_one {
    my $number = shift;
    my $random_number = int(rand(2));
    if ($random_number == 0 and $number > 0) {$number--;}
    if ($random_number == 1 and $number < 9) {$number++;}
    
    return $number;
}


sub put_typos_into {
    my $string = shift;
    my $original_string = $string;
    
    # Append an adjacent number imitating too thick fingers typing two
    # keys at once.
    if ($string =~ m/^[1-9]$/) {
        my $probability = int(rand(25)); # 5
        if ($probability == 0) { # Randomly chosen number
            my $position_where_to_append = int(rand(length($string)-1));
            $string =~ s/^(.{$position_where_to_append,$position_where_to_append})(.)/$1.&plus_one_or_minus_one($1)/e;
            &send_answer($string);
            sleep 1;
            &send_answer($original_string);
            return 0;
        }
    }
    
    # Ja / Nein Questions shall be answered with 'ja' first and the
    # again with 'nein'.
    if ($string =~ m/^(?:(ja)|(nein))$/i) {
        my $probability = int(rand(5)); # 5
        if ($probability == 0) { # Randomly chosen number
            &send_answer('ja');
            sleep 0.75;
            &send_answer('nein');
            return 0;
        }
    }
    
    # Swap adjacent characters.
    if (length($string) > 2) {
        my $probability = int(rand(25)); # 25
        if ($probability == 0) { # Randomly chosen number
            $string = uri_unescape($string);
            my $position_where_to_swap = int(rand(length($string)-1));
            $string =~ s/^(.{$position_where_to_swap,$position_where_to_swap})(.)(.)/$1$3$2/;
            $string = uri_escape($string);
            &send_answer($string);
            sleep 2;
            &send_answer($original_string);
            return 0;
        }
    }
    
    # Append ö, ä, # or + to the string. Do it only in case the last
    # character is a letter.
    if ($string =~ /[a-z]$/) {
        my $probability = int(rand(25)); # 25
        if ($probability == 0) { # Randomly chosen number
            my $character_to_append = int(rand(4));
            $string .= '%C3%B6' if $character_to_append eq 0; # ö: %C3%B6
            $string .= '%C3%A4' if $character_to_append eq 1; # ä: %C3%A4
            $string .= '#' if $character_to_append eq 2;    # #: #
            $string .= '%2B' if $character_to_append eq 3;    # +: %2B
            &send_answer($string);
            return 0;
        }
    }
    # Make the second letter upper case
    if (not $lower_case and $string =~ /^\w\w/) {
        my $probability = int(rand(15)); # 15
        if ($probability == 0) { # Randomly chosen number
            $string =~ s/^(.)(.)/$1\U$2/;
            &send_answer($string);
            return 0;
        }
    }
  # &send_answer($string);
    return 1;
}


sub execute_command {
    my $reason;
    my $netpacket = shift;
    if ($netpacket =~ m!>h(prozedur|motherbrain|kakophonia)#\d+#\d+#a#(.+)</p>!i) {
        print "test\n";
        my $servant = $1;
        my $command = $2;
        # say means to say something in the chat room.
        if ($command =~ m/^say%20(.+)/) {
            $command = $1;
            &send_answer($command);
        }
        # Set means to set new value to a global variable like gathering
        # mode or delay.
        elsif ($command =~ m/^set%20(.+)/) {
            $command = $1;
            print "test set $command\n";
            if ($command eq 'die') {exit;}
            elsif ($command
            =~ m/gather(?:ing)?(?:%20|_)?(?:mode)?(?:%20|%3d)(.+)$/i) {
                print "test bei gather.*\n";
                my $new_value = $1;
                $new_value =~ s/off/0/;
                $gathering_mode = $new_value;
                # gathering_mode and active_mode exclude eacht other
                $active_mode = 0;
            }
            elsif ($command
            =~ m/active(?:%20|_)?(?:mode)?(?:%20|%3D)(.+)$/i) {
                my $new_value = $1;
                $new_value =~ s/off/0/;
                $active_mode = $new_value;
                # gathering_mode and active_mode exclude eacht other
                $gathering_mode = 0;
            }
            elsif ($command =~ m/funny(?:%20|_)?(?:mode)?(?:%20|%3D)(.+)$/i) {
                my $new_value = $1;
                $new_value =~ s/off/0/;
                $funny_mode = $new_value;
            }
            elsif ($command
            =~ m/camo(?:uflage)?(?:%20|_)?(?:mode)?(?:%20|%3d)(.+)$/i) {
                my $new_value = $1;
                $new_value =~ s/off/0/;
                $camouflage_mode = $new_value;
            }
            elsif ($command =~ m/delay(?:%20|%3D)(.+)$/i) {
                my $new_value = $1;
                if ($new_value =~ m/^\d+(?:\.\d+)?$/) {
                    $delay = $new_value;
                }
                else {
                    
                }
            }
            elsif ($command
            =~ m/(?:(?:delay(?:%20|_)?per(?:%20|_)?character)|(?:type(?:%20|_)?(?:speed)?))(?:%20|%3D)(.+)$/i) {
                my $new_value = $1;
                if ($new_value =~ m/^\d+(?:\.\d+)?$/) {
                    $delay_per_character = $new_value;
                }
                else {
                    
                }
            }
            elsif ($command
            =~ m/interval(?:%20|%3D)(\d+)(?:%20|%3D)(\d+)$/i) {
                if ($1 < $2 and
                  $1 > 60 and $1 < 1800 and
                  $2 > 60 and $2 < 1800) {
                    $interval_minimum = $1;
                    $interval_maximum = $2;
                    print "\nmin: $1\nmax: $2\n";
                }
            }
            elsif ($command =~ m/lower(?:%20|_)?(?:case)?(?:%20|%3D)(.+)$/i) {
                my $new_value = $1;
                $new_value =~ s/off/0/;
                $lower_case = $new_value;
            }
            else {
            
            }
        }
        # do means to perform an action like joining or leaving a channel
        elsif ($command =~ m/^do%20(.+)/) {
        # away pause: &msg=W1#a#pause%0AgQuiz3#0#away#1%0A&snd
        # away deakt: &msg=W2#a#     %0AgQuiz3#0#away#0%0A&snd
        #
        # join Quiz:     &msg=oQuiz%0AcQuiz%0A&snd=16&ign=1235405012262
		#                ...
		#                &msg=jQuiz%0A&snd
        # away pause: &msg=W1#a#pause%0AgQuiz3#0#away#1%0A&snd

            $command = $1;
            print "command: $command\n";
			if ($command =~ m/join(?:%20(.+)(?:%20)?)/) {
				my $room_to_join = $1;
				print "command is to join the room: $room_to_join\n";
				$command = "o$room_to_join%0Ac$room_to_join";
				&send_command($command);
				$command = "j$room_to_join";
				&send_command($command);
			}
			# in case message contains the string 'away'
            elsif ($command =~ m/away(?:%20(.+))?/) {
                $reason = $1;
                if ($reason) {
                    $command = "W1#a#$reason%0Ag$room#0#away#1";
                    $command = "W1#a#$reason%0Ag$room#0#away#1";
                }
                else {
                    $command = "W2#a#%0Ag$room#0#away#1";
                }
                &send_command($command);
            }
            # in case message contains close
            elsif ($command =~ m/close%20(.+)/) {
                $room = $1;
                $command = "d$room%0Ac$room";
                &send_command($command);
            }
            # in case message contains quit: terminate the script and exit 
            elsif ($command =~ m/(?:quit|exit)/) {
                print "jetzt logout\n";
                &log_out();
                print "jetzt exit\n";
                sleep 1;
                system("killall $browser");
                exit;
            }
            # Print the current configuration to stdout.
            # in case message contains close
            elsif ($command =~ 
              m/print%20(?:conf(?:iguration)?|set(?:tings?)?)/) {
                print "active_mode: $active_mode\n";
                print "gathering_mode: $gathering_mode\n";
                print "funny_mode: $funny_mode\n";
                print "camouflage_mode: $camouflage_mode\n";
                print "delay: $delay\n";
                print "delay_per_character: $delay_per_character\n";
                print "interval: $interval_minimum, $interval_maximum => $interval\n";
            }
        }
    }
}


sub log_out {
    if (defined $cookie) {
        $get = "/logout?session=$session";
    	$connection = 'keep-alive';
        $useragent->agent($user_agent);
    	$request = HTTP::Request->new(GET =>
    	 'http://www.spin.de'.$get);
    	$request->header('Accept' => $accept_mimetype);
    	$request->header('Accept-Language'	=> $accept_language);
    	$request->header('Accept-Encoding'	=> $accept_encoding);
    	$request->header('Accept-Charset'	=> $accept_charset);
    	$request->header('Keep-Alive' => $keep_alive);
    	$request->header('Connection' => $connection);
    	$request->header('Referer' => 'http://www.spin.de/loggedin');
    	$request->header('Cookie' => $cookie);
    	$response = $useragent->request($request) || die $!;
    }
}


sub send_command {
    if (defined $cookie) {
        my $command = shift;
        my ($seconds, $useconds) = gettimeofday();
        my $time = $seconds.$useconds;
        print "time: ".length($time)."\n";
        $time =~ s/...$//;
        print "time: ".length($time)."\n";
        
        $get =~ m/&snd=(\d+)&ign/;
        my $snd = $1;
        $snd++;
    	$get =~ s/&msg=.+$/&msg=$command%0A&snd=$snd&ign=$time/;

    	$get =~ s/&ign=\d{7,7}/&ign=$time/;
    	$connection = 'keep-alive';
        $useragent->agent($user_agent);
    	$request = HTTP::Request->new(GET =>
    	 'http://html.www.spin.de'.$get);
    	$request->header('Accept' => $accept_mimetype);
    	$request->header('Accept-Language'	=> $accept_language);
    	$request->header('Accept-Encoding'	=> $accept_encoding);
    	$request->header('Accept-Charset'	=> $accept_charset);
    	$request->header('Keep-Alive' => $keep_alive);
    	$request->header('Connection' => $connection);
    	$request->header('Referer' => $referer);
    	$request->header('Cookie' => $cookie);
    	$response = $useragent->request($request);
    }
}


sub send_answer {
    if (defined $cookie) {
    	my $answer = shift;
    	
    	# remove all the hash signs from the answer string before sending
    	$answer =~ s/#//g;
    	
    	print "$room\n";
        my ($seconds, $useconds) = gettimeofday();
        my $time = $seconds.$useconds;
        $time =~ s/...$//;
        
        $get =~ m/&snd=(\d+)&ign/;
        my $snd = $1;
        $snd++;
    	$get =~
    	 s/&msg.+$/&msg=g$room%23a%23$answer%0A&snd=$snd&ign=$time/;

    	$get =~ s/&ign=\d{7,7}/&ign=$time/;
    	$connection = 'keep-alive';
        $useragent->agent($user_agent);
    	$request =
    	 HTTP::Request->new(GET => 'http://html.www.spin.de'.$get);
    	$request->header('Accept' => $accept_mimetype);
    	$request->header('Accept-Language'	=> $accept_language);
    	$request->header('Accept-Encoding'	=> $accept_encoding);
    	$request->header('Accept-Charset'	=> $accept_charset);
    	$request->header('Keep-Alive' => $keep_alive);
    	$request->header('Connection' => $connection);
    	$request->header('Referer' => $referer);
    	$request->header('Cookie' => $cookie);
    	$response = $useragent->request($request);
        system("date >> log.txt");
        system("echo '$answer\n' >> log.txt");
    }
    &generate_variable_interval();
}


sub url_encode_customized {
      my $string = shift;
      $string =~ s/([^\w\.\-\/\~\#\:])/"%" . (sprintf("%2.2X",ord($1)))/eg;
      return $string;
}


sub test_customized_encoder {
    my $string = shift;
    system("echo '$string' > string.txt");
    $string =~ s/^<.+?>//g;
    $string =~ s/<.+?>.*//g;
    my $customized_encoded_string =
      &url_encode_customized(uri_unescape($string));
    
    # I don't know why the control characters do appear at the tail of
    # the strings. Must be something in the unescaping/encoding.
    # They suck.
    $string =~ s/%0a//i;
    $customized_encoded_string =~ s/%0a//i;
    chomp($string);
    chomp($customized_encoded_string);
    
    if (lc($string) ne lc($customized_encoded_string)) {
        print "
        encodings do not match:
origninal: $string
cust-enc:  $customized_encoded_string
        ";
        print "they have changed the url-encoding.\n";
        print "exit immediately.\n";
        exit;
    }
    $string =~ s/(.)/$1\n/g;
    $customized_encoded_string =~ s/(.)/$1\n/g;
}


sub generate_variable_interval {
    $interval = $interval_minimum + int(rand($interval_maximum-
                                                   $interval_minimum));
    system("echo 'interval: $interval' >> log.txt");
}


sub main {
    open(NETTRAFFIC, "sudo tcpdump -i $DEVICE -Aln host 193.254.186.182 or host 193.254.186.183 or host 194.112.167.227 or host 213.95.79.43 -s 0|") or die $!;
    my $question;
    my $previous_question = '';
    my $category;
    my $answer;
    my $still_waiting_for_sending = 1;
    &generate_variable_interval();
    while (<NETTRAFFIC>) {
        &extract_http_values($_);
        &execute_command($_);
        my ($this_time_of_sending, $useconds) = gettimeofday();
        if ($_ =~ m/(Quiz(?:\d|\%2050\%2B)?)#QuizBot(?:\d|\%2050\%2B)?#..#a#%5BFRAGE%5D%20.+%28Kategorie:%20.+%20Punkte:/i){
            $room = $1;
            
            # TODO: Ersetzungen von Zeichen, die die Channelbetreiber
            # mal durch Entitys ersetzen und mal nicht, in extra Routine
            # auslagern.
            $_ =~ s/,/%2C/g;
            
            ($last_time_of_looking_up_answer, $useconds) = gettimeofday();
            &test_customized_encoder($_);
            ($question, $category) = &extract_question($_);
            next if $question eq $previous_question; # sometimes the same netpacket is read twice
            $previous_question = $question;
            $answer = &look_up_answer($_, $category, $question);
            if (defined $answer) {
                if ($lower_case and uri_unescape($answer) =~ m/^\D+$/) {
                    $answer = lc($answer);
                }
                sleep $delay + length($answer) * $delay_per_character;
                $answer = &make_look_funny($answer) if $funny_mode;
                if ($gathering_mode and
                  $this_time_of_sending - $last_time_of_sending > $interval) {
                    sleep 15;
                    if ($camouflage_mode) {
                        $still_waiting_for_sending = &put_typos_into($answer);
                    }
                    if ($still_waiting_for_sending) {
                        &send_answer($answer);
                    }
                    $last_time_of_sending = $this_time_of_sending;
                }
                if ($active_mode) {
                    if ($camouflage_mode) {
                        $still_waiting_for_sending = &put_typos_into($answer);
                    }
                    if ($still_waiting_for_sending) {
                        &send_answer($answer);
                    }
                } 
            }
        }
        elsif ($_ =~ m/(Quiz(?:\d|\%2050\%2B)?).+(?:Antwort%20lautet|ist%20richtig)/
        and defined $category and not defined $answer) {
            &extract_answer($_, $category, $question) if $1 eq $room;
            $answer = undef;
        }
        #&msg=hQuizBot#1#c#winkt%20zum%20Abschied%2E%0A
        elsif ($_ =~ m!&msg=gQuiz(?:\d|\%2050\%2B)?#[ac]#winkt%20zum%20Abschied%2E%0A!
        or $_ =~ m!#\d+#\d+#a#do%20quit!) {
            last;
        }
        # In case sammler.pl is the only user in channel QuizBot will stop
        # asking questions so the idle preventing routine will fail. The
        # following block sends therefore a standard string in order not
        # to be removed from channel.
        elsif ($gathering_mode
        and $this_time_of_sending - $last_time_of_sending > ($interval+60)) {
            sleep 5;
            &send_answer("mach hin bot");
            $last_time_of_sending = $this_time_of_sending;
        }
    }
    close(NETTRAFFIC);
}

&main();
