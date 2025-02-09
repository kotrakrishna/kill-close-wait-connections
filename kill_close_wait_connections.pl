#!/usr/bin/perl
# Originally created by mirage 2014
use strict;
use Socket;
use Net::RawIP;
use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;
use POSIX qw(setsid);
use warnings;

# Ensure prev.txt file exists
system("touch /tmp/prev.txt");
# Get current set of close wait connections in sorted order
system("netstat -tulnap | grep CLOSE_WAIT | sed -e 's/::ffff://g' | awk '{print \$4,\$5}' | sed 's/:/ /g' | sort > /tmp/curr.txt");
# Log common lines into a file
system("comm -12 /tmp/prev.txt /tmp/curr.txt > /tmp/killed.txt")
# Common lines into the connections wait variable
open(my $CONNECTIONS_WAIT, "comm -12 /tmp/prev.txt /tmp/curr.txt |") || die "Failed: $!\n";

while ( my $conn = <$CONNECTIONS_WAIT> )
{
    chomp $conn;
    my ($src_ip, $src_port, $dst_ip, $dst_port) = split(' ', $conn);

    my $packet = Net::RawIP->new({
       ip => {  frag_off => 0, tos => 0,
       saddr => $dst_ip, daddr => $src_ip
       },
       tcp =>{  dest => $src_port, source => $dst_port,
       seq => 10, ack => 1
       }
       });
    $packet->send;
}

# empty prev.txt file. Redundant
system("echo '' > /tmp/prev.txt");
# record new set of close wait connections
system("netstat -tulnap | grep CLOSE_WAIT | sed -e 's/::ffff://g' | awk '{print \$4,\$5}' | sed 's/:/ /g' | sort > /tmp/prev.txt");
