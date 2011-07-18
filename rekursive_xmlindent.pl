use warnings;
use strict;

my $directory = 'inventories/';
opendir(INVENTORIES, $directory) or die $!;
my @files = grep { m/xml$/ } sort readdir(INVENTORIES);
closedir(INVENTORIES);

foreach my $file (@files) {
  if ($file =~ m/\.xml$/) {
    qx(xmlindent -w "$directory$file");
    print "$file\n";
  }
}

# Damit es den Namen "rekursiv" halbwegs verdient.
qx(xmlindent -w "$directory/Computer/EDV.xml");

system("rm -r $directory/*~");
