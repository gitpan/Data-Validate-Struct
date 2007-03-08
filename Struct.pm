#
# Copyright (c) 2007 Thomas Linden <tlinden |AT| cpan.org>.
# All Rights Reserved. Std. disclaimer applies.
# Artificial License, same as perl itself. Have fun.
#
# namespace
package Data::Validate::Struct;

use strict;
use warnings;
use English '-no_match_vars';
use Carp;
use Exporter;
#use Data::Dumper;

use Regexp::Common::URI::RFC2396 qw /$host $port/;
use Regexp::Common qw /URI net delimited/;

use File::Spec::Functions qw/file_name_is_absolute/;
use File::stat;

use Data::Validate qw(:math is_printable);

use constant FALSE => 0;
use constant TRUE  => 1;

$Data::Validate::Struct::VERSION = 0.06;

use vars  qw(@ISA);

sub new {
  my( $this, $structure ) = @_;
  my $class = ref($this) || $this;

  my $self;
  $self->{structure} = $structure;

  #
  # if types will be implemented in Data::Validate, remove our own
  # types from here and use Data::Validate's methods as subroutine
  # checks, which we already support.
  $self->{types} = {
		    # primitives
		    int            => sub { return defined(is_integer($_[0])); },
		    hex            => sub { return defined(is_hex($_[0])); },
		    oct            => sub { return defined(is_oct($_[0])); },

		    # FIXME: add is_between argumented types, need more than one argument

		    number         => sub { return defined(is_numeric($_[0])); }, # abandoned: qr(^$RE{num}{decimal}$),
		    word           => qr(^[\w_\-]+$),
		    line           => qr/^[^\n]+$/s,

		    text           => sub { return defined(is_printable($_[0])); }, # abandoned: qr/.+/s,

		    # this is a bit loosy but should match most regular expressions
		    # using the qr() operator, but it doesn't check if the expression
		    # is valid. we could do this by compiling it, but this would lead
		    # to exploitation possiblities to programs using the module.
		    regex          => qr/^qr ( (.).*\1 | \(.*\) | \{.*\} ) $/x,

		    # via imported regexes
		    uri            => qr(^$RE{URI}$),
		    # FIXME: use Data::Validate::IP here
		    cidrv4         => qr/^$RE{net}{IPv4} \/ ( [0-9] | [12][0-9] | 3[0-2] )$/x,
		    ipv4           => qr/^$RE{net}{IPv4}$/,
                    quoted         => qr/^$RE{delimited}{ -delim => qr(\') }$/,
		    hostname       => qr(^$host$),

		    # IPv6 addresses
		    # well, this expression is very complicated - I found it on:
		    # http://blogs.msdn.com/mpoulson/archive/2005/01/10/350037.aspx
		    # Thanks to Mike Poulson!
		    # Interesting side note: those expressions were written for
		    # VB.net - since it works here unchanged, I think they use PCRE :-)
		    ipv6           => qr/^
					 (
                                           (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}
					 )
                                         |
					 (
                                           ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::
                                             ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)
					 )
                                         |
					 (
                                           ((?:[0-9A-Fa-f]{1,4}:){6,6})(25[0-5]|2[0-4]\d|
                                                      [0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}
					 )
                                         |
					 (
                                           ((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)
                                                      ::((?:[0-9A-Fa-f]{1,4}:)*)(25[0-5]|2[0-4]\d|
                                                      [0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}
					 )
                                        $/x,

		    # matches perl style scalar variables
		    # possible matches: $var ${var} $(var)
		    vars           => qr/(?<!\\) ( \$\w+ | \$\{[^\}]+\} | \$\([^\)]+\) )/x,

		    # closures

		    # this one doesn't do a stat() syscall, so keep cool
		    path           => sub { return file_name_is_absolute($_[0]); },

		    # though this one does it - it stat()s if the file exists
		    fileexists     => sub { return stat($_[0]); },

		    # do a dns lookup on given value, this also fails if
		    # no dns is available - so be careful with this
		    resolvablehost => sub { return gethostbyname($_[0]); },

		    # looks if the given value is an existing user on the host system
		    user           => sub { return (getpwnam($_[0]))[0]; },

		    # same with group
		    group          => sub { return getgrnam($_[0]); },

		    # int between 0 - 65535
		    port           => sub { if ( $_[0] =~ /^$port$/ && ($_[0] > 0 && $_[0] < 65535) ) { return 1; } else { return 0; } },

		    };

  $self->{debug} = 0;

  foreach my $type (%{$self->{types}}) {
    # add negative match types
    $self->{types}->{'no' . $type} = $self->{types}->{$type};
  }

  bless $self, $class;

  return $self;
}


sub type {
  my ($this, %param) = @_;
  foreach my $type (keys %param) {
    $this->{types}->{$type} = $param{$type};
  }
}


sub debug {
  my ($this) = @_;
  $this->{debug} = 1;
}

sub errstr {
  my ($this) = @_;
  if (exists $this->{error}) {
    return $this->{error};
  }
}

sub validate {
  my($this, $config) = @_;

  eval {
    $this->traverse($this->{structure}, $config);
  };
  if ($@) {
    $this->{error} = $@;
    return FALSE;
  }
  else {
    return TRUE;
  }
}

sub _debug {
  my ($this, $msg) = @_;
  if ($this->{debug}) {
    print STDERR "::Validate::debug() - $msg\n";
  }
}

sub traverse {
  my($this, $a, $b) = @_;

  foreach my $key (keys %{$a}) {

    if (ref($a->{$key}) eq 'ARRAY') {
      # just use the 1st one, more elements in array are expected to be the same
      foreach my $item (@{$b->{$key}}) {
	if (ref($item) eq q(HASH)) {
	  $this->traverse($a->{$key}->[0], $item);
	}
	else {
	  # a value, this is tricky
	  $this->traverse({item => $a->{$key}->[0]}, { item => $item});
	}
      }
    }
    elsif (ref($a->{$key}) eq 'HASH') {
      $this->traverse($a->{$key}, $b->{$key});
    }
    elsif (grep {ref($a->{$key}) ne $_} qw(GLOB REF CODE LVALUE) ) {
      # check data type
      if (! exists $this->{types}->{$a->{$key}}) {
	croak qq(Invalid data type "$a->{$key}");
      }
      else {
	if (exists $b->{$key}) {
	  if ($a->{$key} =~ /^no\s*/) {
	    $this->check_type($a->{$key}, $key, $b->{$key}, sub{ die $_[0]; }, sub {});
	  }
	  else {
	    $this->check_type($a->{$key}, $key, $b->{$key}, sub{}, sub{ die $_[0]; });
	  }
	}
	else {
	  die "requred $key doesn't exist in hash\n";
	}
      }
    }
  }
}

sub check_type {
  my($this, $type, $name, $value, $true, $false) = @_;

  if (ref($this->{types}->{$type}) eq q(CODE)) {
    # execute closure
    my $sub = $this->{types}->{$type};
    if (! &$sub($value)) {
      $this->_debug( "$name = $value, value is not $type");
      die "$name = $value, value is not $type";
    }
    else {
      $this->_debug( "$name = $value, value is $type");
    }
  }
  else {
    if ($value =~ /$this->{types}->{$type}/) {
      $this->_debug( "$name = $value, value doesn't match /$type/");
      &$true( "$name = $value, value doesn't match /$type/\n");
    }
    else {
      $this->_debug( "$name = $value, value matches /$type/");
      &$false( "$name = $value, value doesn't match /$type/\n");
    }
  }

}


1;


__END__

=head1 NAME

Data::Validate::Struct - Validate recursive Hash Structures

=head1 SYNOPSIS

 use Data::Validate::Struct;
 my $validator = new Data::Validate::Struct($reference);
 if ( $validator->validate($config_hash_reference) ) {
   print "valid\n";
 }
 else {
   print "invalid " . $validator->errstr() . "\n";
 }

=head1 DESCRIPTION

This module validates a config hash reference against a given hash
structure in contrast to L<Data::Validate> in which you have to
check each value separately using certain methods.

This hash could be the result of a config parser or just any
hash structure. Eg. the hash returned by L<XML::Simple> could
be validated using this module. You may also use it to validate
CGI input, just fetch the input data from CGI, L<map> it to a
hash and validate it.

Data::Validate::Struct uses some of the methods exported by L<Data::Validate>,
so you need to install it too.


=head1 PREDEFINED BUILTIN DATA TYPES

=over

=item B<int>

Match a simple integer number.

=item B<hex>

Match a hex value.

=item B<oct>

Match an octagonal value.

=item B<number>

Match a decimal number, it may contain , or . and may be signed.

=item B<word>

Match a single word, _ and - are tolerated.

=item B<line>

Match a line of text - no newlines are allowed.

=item B<text>

Match a whole text(blob) including newlines. This expression
is very loosy, consider it as an alias to B<any>.

=item B<regex>

Match a perl regex using the operator qr(). Valid examples include:

 qr/[0-9]+/
 qr([^%]*)
 qr{\w+(\d+?)}

Please note, that this doesn't mean you can provide
here a regex against config options must match.

Instead this means that the config options contains a regex.

eg:

 <cfg>
   grp  = qr/root|wheel/
 </cfg>

B<regex> would match the content of the variable 'grp'
in this example.

To add your own rules for validation, use the B<type()>
method, see below.

=item B<uri>

Match an internet URI.

=item B<ipv4>

Match an IPv4 address.

=item B<cidrv4>

The same as above including cidr netmask (/24), IPv4 only, eg:

 10.2.123.0/23

Note: shortcuts are not supported for the moment, eg:

 10.10/16

will fail while it is still a valid IPv4 cidr notation for
a network address (short for 10.10.0.0/16). Must be fixed
in L<Regex::Common>.

=item B<ipv6>

Match an IPv6 address. Some examples:

 3ffe:1900:4545:3:200:f8ff:fe21:67cf
 fe80:0:0:0:200:f8ff:fe21:67cf
 fe80::200:f8ff:fe21:67cf
 ff02:0:0:0:0:0:0:1
 ff02::1

=item B<quoted>

Match a text quoted with single quotes, eg:

 'barbara is sexy'

=item B<hostname>

Match a valid hostname, it must qualify to the definitions
in RFC 2396.

=item B<resolvablehost>

Match a hostname resolvable via dns lookup. Will fail if no
dns is available at runtime.

=item B<path>

Match a valid absolute path, it won't do a stat() system call.
This will work on any operating system at runtime. So this one:

 C:\Temp

will return TRUE if running on WIN32, but FALSE on FreeBSD!

=item B<fileexists>

Look if value is a file which exists. Does a stat() system call.

=item B<user>

Looks if the given value is an existent user. Does a getpwnam() system call.

=item B<group>

Looks if the given value is an existent group. Does a getgrnam() system call.

=item B<port>

Match a valid tcp/udp port. Must be a digit between 0 and 65535.

=item B<vars>

Matches a string of text containing variables (perl style variables though)
eg:

 $user is $attribute
 I am $(years) old
 Missing ${points} points to succeed

=back



=head1 NEGATIVE MATCHING

In some rare situations you might require a negative match. So
a test shall return TRUE if a particular value does NOT match the
given type. This might be usefull to prevent certain things.

To achieve this, you just have to prepend one of the below mentioned
types with the keyword B<no>.

Example:

 $ref = { path => 'novars' }

This returns TRUE if the value of the given config hash does NOT
contain ANY variables.


=head1 VALIDATOR STRUCTURE

The expected structure must be a standard perl hash reference.
This hash may look like the config you are validating but
instead of real-live values it contains B<types> that define
of what type a given value has to be.

In addition the hash may be deeply nested. In this case the
validated config must be nested the same way as the reference
hash.

Example:

 $reference = { user => 'word', uid => 'int' };

The following config would be validated successful:

 $config = { user => 'HansDampf',  uid => 92 };

this one not:

 $config = { user => 'Hans Dampf', uid => 'nine' };
                          ^                ^^^^
                          |                |
                          |                +----- is not a number
                          +---------------------- space not allowed

For easier writing of references you yould use a configuration
file parser like Config::General or Config::Any, just write the
definition using the syntax of such a module, get the hash of it
and use this hash as validation reference.

=head1 NESTED HASH STRUCTURES

You can also match against nested structures. B<Data::Validate::Struct> iterates
into the given config hash the same way as the reference hash looks like.

If the config hash doesn't match the reference structure, perl will
throw an error, which B<Data::Validate::Struct> catches and returns FALSE.

Given the following reference hash:

 $ref = {
 'b1' => {
          'b2' => {
                   'b3' => {
                            'item' => 'int'
                           }
                  }
          }
 }

Now if you validate it against the following config hash it
will return TRUE:

 $cfg = {
 'b1' => {
	  'b2' => {
		   'b3' => {
			    'item' => '100'
			   }
		  }
	 }
 }

If you validate it for example against this hash, it will
return FALSE:

 $cfg = {
 'b1' => {
	  'b2' => {
		    'item' => '100'
		   }
	 }
 }

=head1 SUBROUTINES/METHODS

=over

=item B<validate($config)>

$config must be a hash reference you'd like to validate.

It returns a true value if the given structure looks valid.

If the return value is false (0), then the error message will
be written to the variable $!.

=item B<type(%types)>

You can enhance the validator by adding your own rules. Just
add one or more new types using a simple hash using the B<type()>
method. Values in this hash can be regexes or anonymous subs.

Example:

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

In this example we add 2 new types, 'list' and 'address', which
are really simple. 'address' is a regex which matches a word
followed by an integer. 'list' is a subroutine which gets called
during evaluation for each option which you define as type 'list'.

Such subroutines must return a true value in order to produce a match.

You can also add reversive types, which are like all other types
but start with B<no>. The validator does a negative match in such a
case, thus you will have a match if a variable does B<not> match
the type. The builtin type 'novars' is such a type.

Regexes will be executed exactly as given. No flags or ^ or $
will be used by the module. Eg. if you want to match the whole
value from beginning to the end, add ^ and $, like you can see
in our 'address' example above.

=item B<debug()>

Enables debug output which gets printed to STDERR.

=item B<errstr()>

Returns the last error, which is useful to notify the user
about what happened.

=back

=head1 ARRAYS

Arrays must be handled in a special way, just define an array
with two elements and the second empty. The config will only
validated against the first element in the array.

We assume all elements in an array must have the same structure.

Example for array of hashes:

 $reference = {
                [
                  {
                     user => 'word',
                     uid => 'int'
                  },
                  {} # empty 2nd element
                ]
               };

Example of array of values:

 $reference = {
  var => [ 'int', '' ]
 }

=head1 EXAMPLES

Take a look to F<t/run.t> for lots of examples.

=head1 CONFIGURATION AND ENVIRONMENT

No environment variables will be used.

=head1 SEE ALSO

I recommend you to read the following documentations, which are supplied with perl:

L<perlreftut> Perl references short introduction.

L<perlref> Perl references, the rest of the story.

L<perldsc> Perl data structures intro.

L<perllol> Perl data structures: arrays of arrays.

L<Data::Validate> common data validation methods.

=head1 LICENSE AND COPYRIGHT

Copyright (c) 2007 Thomas Linden

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 BUGS AND LIMITATIONS

Some implementation details as well as the API may change
in the future. This will no more happen if entering a stable
release (starting with 1.00).

To submit use L<http://rt.cpan.org>.

=head1 INCOMPATIBILITIES

None known.

=head1 DIAGNOSTICS

To debug Data::Validate::Struct use B<debug()> or the perl debugger, see L<perldebug>.

For example to debug the regex matching during processing try this:

 perl -Mre=debug yourscript.pl

=head1 DEPENDENCIES

Data::Validate::Struct depends on the module L<Data::Validate>,
L<Regexp::Common>, L<File::Spec> and L<File::stat>.

=head1 TODO

=over

=item *

Add support for type mixes, such as:

 { name => 'int|number' }

=item *

Add support for ranges, in fact L<Regexp::Common> or L<Data::Validate> already
supports this, but B<Data::Validate::Struct> currently doesn't support
parameters for types.

=item *

Perhaps add code validation too, for example we could have
a type 'perl' which tries to evaluate the given value. On the
other side this may lead to security holes - so I might never do it.

=item *

Plugin System

=item *

Possibly add support for grammars. This might be much more powerful
than regular expressions, say:

 { name => 'expr OP expr | expr' }

or something like this.

=back

=head1 AUTHOR

Thomas Linden <tlinden |AT| cpan.org>

Thanks to David Cantrell for his helpful hints.

=head1 VERSION

0.06

=cut

