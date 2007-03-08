# -*-perl-*-
use Test::More tests => 19;
#use Test::More qw(no_plan);

use lib qw(.);

print STDERR "\n";
require_ok( 'Data::Validate' );

my $ref = {
	   'v4' => 'line',
	   'v15' => 'fileexists',
	   'item' => [
                      'number',
                      ''
		     ],
	   'v5' => 'text',
	   'v17' => 'regex',
	   'v6' => 'hostname',
	   'v12' => 'cidrv4',
	   'v18' => 'novars',
	   'v11' => 'uri',
	   'v3' => 'word',
	   'v8' => 'user',
	   'v1' => 'int',
	   'v14' => 'path',
	   'v2' => 'number',
	   'v10' => 'port',
	   'b1' => {
                    'b2' => {
			     'b3' => {
				      'item' => 'int'
				     }
                            }
		   },
	   'v13' => 'ipv4',
	   'v16' => 'quoted',
	   'v19' => 'ipv6',
	   'v20' => 'ipv6',
	   'v21' => 'ipv6',
	   'v22' => 'ipv6',
	   'v23' => 'ipv6'
	  };

my $cfg =  {
	    'v19' => '3ffe:1900:4545:3:200:f8ff:fe21:67cf',
	    'v20' => 'fe80:0:0:0:200:f8ff:fe21:67cf',
	    'v21' => 'fe80::200:f8ff:fe21:67cf',
	    'v22' => 'ff02:0:0:0:0:0:0:1',
	    'v23' => 'ff02::1',
	    'v4' => 'this is a line of text',
	    'v15' => 'MANIFEST',
	    'item' => [
		       '10',
		       '20',
		       '30'
		      ],
	    'v5' => 'This is a text block
                     This is a text block',
	    'v17' => 'qr([0-9]+)',
	    'v6' => 'search.cpan.org',
	    'v12' => '192.168.1.101/18',
	    'v18' => 'Doesnt contain any variables',
	    'v11' => 'http://search.cpan.org/~tlinden/?ignore&not=1',
	    'v3' => 'Johannes',
	    'v8' => 'root',
	    'v1' => '123',
	    'v14' => '/etc/ssh/sshd.conf',
	    'v2' => '19.03',
	    'v10' => '22',
	    'b1' => {
		     'b2' => {
                              'b3' => {
				       'item' => '100'
                                      }
			     }
		    },
	    'v13' => '10.0.0.193',
	    'v16' => '\' this is a quoted string \''
	   };

my $v = new Data::Validate($ref);
ok ($v->validate($cfg), "validate a reference against a config " . $v->errstr());



# check failure matching
my @failure =
(
 { cfg  => q(acht),
   type => q(int)
 },

 { cfg  => q(27^8),
   type => q(number)
 },

 { cfg  => q(two words),
   type => q(word)
 },

 { cfg  => qq(<<EOF\nzeile1\nzeile2\nzeile3\nEOF\n),
   type => q(line)
 },

 { cfg  => q(ätz),
   type => q(hostname)
 },

 { cfg  => q(gibtsnet123456790.intern),
   type => q(resolvablehost)
 },

 { cfg  => q(äüö),
   type => q(user)
 },

 { cfg  => q(äüö),
   type => q(group)
 },

 { cfg  => q(234234444),
   type => q(port)
 },

 { cfg  => q(unknown:/unsinnüäö),
   type => q(uri)
 },

 { cfg  => q(1.1.1.1/33),
   type => q(cidrv4)
 },

 { cfg  => q(300.1.1.1),
   type => q(ipv4)
 },

 { cfg  => q(üäö),
   type => q(fileexists)
 },

 { cfg  => q(not quoted),
   type => q(quoted)
 },

 { cfg  => q(no regex),
   type => q(regex)
 },

 { cfg  => q($contains some $vars),
   type => q(novars)
 }
);

foreach my $test (@failure) {
  my $ref    = { v => $test->{type} };
  my $cfg    = { v => $test->{cfg}  };
  my $v      = new Data::Validate($ref);
  if ($v->validate($cfg)) {
    fail("could not catch invalid \"$test->{type}\"");
  }
  else {
    pass ("catched invalid \"$test->{type}\"");
  }
}



# adding custom type
my $ref3 = { v1 => 'address',
	     v2 => 'list' };
my $cfg3 = { v1 => 'Marblestreet 15',
	     v2 => 'a1, b2, b3' };
my $v3   = new Data::Validate($ref3);
$v3->type(
 (
  address => qr(^\w+\s\s*\d+$),
  list    =>
    sub {
      my $list = $_[0];
      my @list = split /\s*,\s*/, $list;
      if (scalar @list > 1) {
	return 1;
      }
      else {
	return 0;
      }
    }
 )
);
ok($v3->validate($cfg3), "using custom types " . $v3->errstr());


