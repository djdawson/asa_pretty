#!/usr/bin/perl
#
# Perl script to "pretty print" an ASA (or PIX) config with the following features:
#
# - Insert "!" comment lines between groups of related commands for better readability,
#   such as between access-lists, object groups, and crypto config sections.  This was
#   all the original awk version of this script did.
#
# - Group "route" and "static" commands together by interface or "(int,int)" pair.
#
# - Intelligently substitute "name" definitions elsewhere in the config, factoring in
#   whether the "no names" command is present as well as the ASA software version,
#   since the behavior of "name" changed substantially in 8.3.
#
# - Intelligently expand extended access-lists to show the net effect of all "object"
#   and "object-group" element substitution.  The original line is "remarked" out, and
#   the expanded lines are indented to make it clear which lines were expanded.
#
# - Include the defined object in "object nat" definitions as a comment before the
#   "nat" command so that it's easier to see which IP addresses are being natted.
#
# - Expand objects referenced in global nat commands for easier reference and list
#   them as comments after the referencing nat statement.
#
# This script is the result of an evolution from a simple awk script to process PIX
# configs, to a Perl script created by the "a2p" utility, to a series of three different
# Perl scripts to handle the "static" and "route" commands, name substitution, and
# object expansion, to this single monolithic script that does it all.
#
# To Do:  - Add "getopt" to make some features optional and/or overrideable.
#
# Written by:  Dana J. Dawson
#              CCIE #1937
#
# Final Version:  October, 2014
#

use strict;
use warnings;

my @fld = ();           # Array for the fields the input line gets split into
my @prev = ("" x 6);    # Array for up to the first 6 fields from the previous line
my %routes = ();        # Hash for processing "route" commands per-interface
my %statics = ();       # Hash for processing "static" commands per interface combination (pre 8.3)
my $addr = "";          # Address field from "name" command;
my $name = "";          # Name field from "name" command;
my %names = ();         # Hash for saving "name" definitions.  Only one value per name, so a simple hash is fine.
my @config1 = ();       # Array for saving config for Pass 1 processing.  Easier than trying to do it all in one pass.
my @config2 = ();       # Array for saving config for Pass 2 processing.
my $version = 0;        # ASA/PIX Version value, so we can try to be smart about syntax handling.
my $pre83 = 0;          # Flag for if Version is pre-8.3, since "name" support changed a lot in 8.3.
my $skip_names = 0;     # Flag for turning off "name" substitution.

my $gname = "";         # Group Name
my %objects = ();       # Hash for references to "object" and "object-group" arrays.

LINE1: while (<>) {     # Begin Pass 1
    chomp;
    s/\r//g;                # Remove any Carriage Return characters (Windows line endings).
    s/\s+$//;               # Remove any trailing white space.
    s/<--- More --->//i;    # Remove any "More" prompts that might be present.
    s/ {14}//;              # Remove the 14 spaces that often follow a "More" prompt, maybe on next line.

    if (/^\s*$/) {          # Skip any completely blank lines, which might happen after removing
        next LINE1;         #  any "More" prompts, since those prompts might span two lines (e.g. putty logs).
    }
    
    if (/^(?:ASA|PIX)\s+Version/) {   # Check the PIX/ASA software version, since "name" support changed in 8.3
        ($version) = /^ASA Version\s+(\d+\.\d+)/;
        $version = 8.3 unless $version;         # If no version, assume 8.3, since that's less likely
        $pre83 = ($version < 8.3) ? 1 : 0;      #  to break the config with a bad name substitution.
    }

    if (/^no names/) {      # If we see a "no names" command then set the "$skip_names" flag for later, since
        $skip_names = 1;    #  "name" replacement won't apply (though "object" substitution still might...)
    }

    if (/^name\s+/) {
        ($addr, $name) = /name\s+(\S+)\s+(\S+)/;
        $names{$name} = $addr;
    }

    if (/^object network/) {      # If we see an "object network" command then assume 8.3, since that's when that
        $pre83 = 0;               #  command appeared.  In case the version in the config is missing or wrong...
    }

    @fld = split;
    shift @fld if $fld[0] eq "no";  # Skip first field if it's "no" for easier checks for command blocks.

    if (/^\s/) {                # If a line is indented assume it's in a block and don't change "@prev".
        push(@config1, $_);
        next LINE1;
    }

    if (/^:/) {                 # Save existing ":" lines, since they're just comments.
        push(@config1, $_);;
        $prev[0] = ':';         # Remember these lines so we don't put a "!" line after them.
        next LINE1;
    }

    if (/^!/) {     # Save existing "!" lines, but not multiple consecutive ones, and not after ":" lines.
        if ($prev[0] ne '!' && $prev[0] ne ':') {
            push(@config1, $_);
            $prev[0] = '!';
        }
        next LINE1;
    }

    if (/^static/) {    # "static" commands are special.  Loop through all of them and group by "(int,int)" pair.
        while (/^static/) {
            if ( !(defined $statics{$fld[1]}) ) {
                push(@{$statics{$fld[1]}}, "!");
            }
            push(@{$statics{$fld[1]}}, $_);
            $_ = get_line();        # We should probably error check here, but a partial config is unlikely...
            chomp;
            @fld = split;
        }
        foreach my $k (keys %statics) {
            foreach my $line (@{$statics{$k}}) {
                push(@config1, "$line");
            };
        }
        $prev[0] = 'static';
    }

    if (/^route /) {     # "route" commands are special.  Loop through all of them and group by interface.
        while (/^route/) {
            if ( !(defined $routes{$fld[1]}) ) {
                push(@{$routes{$fld[1]}}, "!");
            }
            push(@{$routes{$fld[1]}}, $_);
            $_ = get_line();        # We should probably error check here, too.
            @fld = split;
        }
        foreach my $k (keys %routes) {
            foreach my $line (@{$routes{$k}}) {
                push(@config1, "$line");
            };
        }
        $prev[0] = 'route';
    }

    #
    # Process commands with 6 significant leading keywords:
    #
    if (/^class-map/) {
        if (($fld[0] ne $prev[0] ||
             $fld[1] ne $prev[1] ||
             $fld[2] ne $prev[2] ||
             $fld[3] ne $prev[3] ||
             $fld[4] ne $prev[4] ||
             $fld[5] ne $prev[5]) && $prev[0] !~ /[:!]/) {
            push(@config1, "!");
        }
        push(@config1, $_);
        @prev[0..5] = @fld[0..5];
        next LINE1;
    }

    #
    # Process commands with 4 significant leading keywords:
    #
    if (/^crypto|policy-map/) {
        if (($fld[0] ne $prev[0] ||
             $fld[1] ne $prev[1] ||
             $fld[2] ne $prev[2] ||
             $fld[3] ne $prev[3]) && $prev[0] !~ /[:!]/) {
            push(@config1, "!");
        }
        push(@config1, $_);
        @prev[0..3] = @fld[0..3];
        next LINE1;
    }

    #
    # Process commands with 3 significant leading keywords:
    #
    if (/^(object |object-group|isakmp)/) {
        if (($fld[0] ne $prev[0] ||
             $fld[1] ne $prev[1] ||
             $fld[2] ne $prev[2]) && $prev[0] !~ /[:!]/) {
            push(@config1, "!");
        }
        push(@config1, $_);
        @prev[0..2] = @fld[0..2];
        next LINE1;
    }

    #
    # Process commands with 2 significant leading keywords:
    #
    if (/^(ip |access-list|aaa-server|group-policy|username|tunnel-group|vpngroup)/) {
        if (($fld[0] ne $prev[0] ||
             $fld[1] ne $prev[1]) && $prev[0] !~ /[:!]/) {
            push(@config1, "!");
        }
        push(@config1, $_);
        @prev[0..1] = @fld[0..1];
        next LINE1;
    }

    #
    # Process commands with just 1 significant leading keyword (i.e. most other commands):
    #
    if ($fld[0] ne $prev[0]) {
        if ($prev[0] !~ /[:!]/ && $. > 1) {   # Don't save "!" line as first line or after ":" lines
            push(@config1, "!");
        }
        push(@config1, $_);
        $prev[0] = $fld[0];
        next LINE1;
    }

    if ($fld[0] eq $prev[0]) {
        push(@config1, $_);
    }
}

foreach (@config1) {    # Last part of Pass 1 - "name" substitution.
    if (!$skip_names) {     # Replace names unless there was a "no names" command in the config.
        # Don't replace "names" in the commands below:
        if ( !/^(name\s|access-list|\s*nat|object network|object-group|\s*description|\s*port-forward)|\s*network-object object/ ) {
            foreach my $n (keys %names) {
                s/\b$n\b/$names{$n}/;       # This modifies the current line in "@config1" array via $_ !!!
            }
        }
        if ( /^access-list/ && $pre83 ) {   # Special case for "access-list" in pre-8.3 ASA code
            foreach my $n (keys %names) {
                s/\b$n\b/$names{$n}/;       # This modifies the current line in "@config1" array via $_ !!!
            }
        }
    }
}

# Begin Pass 2 - "object" and "object-group" substitution.
# We create a new "@config2" array because it easier than inserting lines
# into an existing array.
#
LINE2: foreach (@config1) {

# Read each input line.
# If a line starts with "object-group" or "object [network|service]", start a new group
# named with the third field on the line.  We'll use "$gname" as a state variable later
# so we'll know if we're processing an "object.*" block or not.
#
    if (/^(?:object-group|object\s+(?:network|service))/) {
        ($gname) = /^\S+\s+\S+\s+(\S+)/;
        push(@config2, $_);
        next LINE2;
    }

# Add the individual "object*" definition lines to the current group array, "${objects{$gname}}".
# If we find a "group-object" line in an ACL, change it to "object-group" and save it in the array, since the recursive
# subroutine "acl_obj_grp" will take care of expanding the referenced object-group (in ACL's only!).  Cool, ain't it?
# Also, strip off any ".*-object", "subnet", or "service" keywords, as well as any leading or trailing white
# space, since the remaining part of the line is the correct replacement syntax for later.  For
# "object (network|service)" objects, just save the subsequent line (as long as it's not a "nat"
# or "description" command), since they're much more complex and we'll deal with them later.
#
    if ($gname && /^\s/) {
        if ( !/^\s*(?:nat|description)/ ) {
            (my $tmp = $_) =~ s/^\s*group-object/object-group/;
            $tmp =~ s/^\s*(?:\S+-object|subnet|service)\s+//;
            $tmp =~ s/\s+$//;
            $tmp =~ s/^\s+//;
            if ($tmp =~ /^object\s+(\S+)/) {            # Check for "object" substitution in "object-groups"
                my $tmp_obj_name = $1;                  # The ASA syntax only allows a simple object here,
                $tmp = ${$objects{$tmp_obj_name}}[0];   #  so we only have to substitute a single object from
                push(@config2, $_);                     #  the saved "%objects" hash element.
                s/^.*$/ ! OBJECT DEFINITION:  $tmp_obj_name = $tmp/;  #  We change $_ here!!!
            }
            push(@{$objects{$gname}}, $tmp);
        }
        if (/^\s*nat/) {    # If we see a "nat" command here push the matching object into the config as a comment.
            my $tmp = " ! NAT FROM: " . $objects{$gname}[0];        # We know there's only one object element for "object nat".
            $tmp =~ s/FROM: /FROM: subnet / unless $tmp =~ /host/;  # Put "subnet" back in if not a "host" object.
            push(@config2, $tmp);
            my %seen = ();              # Check for any objects on the nat command and expand them, just like global nat below
            @fld = split;
            for (my $i = 3; $i <= $#fld; $i++) {                        # The first 3 fields on a nat can't be objects, so skip them
                if ( !($seen{$fld[$i]}) && $objects{$fld[$i]} ) {       # We found a new object name
                    $seen{$fld[$i]} = 1;                                # Remember that we've seen it
                    push(@config2, " ! NAT TO OBJECT:  $fld[$i]");
                    foreach ( expand_object( @{$objects{$fld[$i]}} ) ) {    # Expand the object and output each element
                        push(@config2, " !   $_");
                    }
                }
            }
        }
        push(@config2, $_);
        next LINE2;
    }

# If we get here we're not in an "object*" stanza, so reset $gname.
#
    $gname = "";

# For global nat commands (i.e. any that aren't "object-nat"), expand any group references we find
# as comments for easier reference.  This is more complex than one would expect...
#
    if (/^nat/) {                                                   # We found a global nat command
        push(@config2, $_);                                         # Output it. We'll expand any object names we find next...
        my %seen = ();
        @fld = split;
        for (my $i = 3; $i <= $#fld; $i++) {                        # The first 3 fields on a nat can't be objects, so skip them
            if ( !($seen{$fld[$i]}) && $objects{$fld[$i]} ) {       # We found a new object name
                $seen{$fld[$i]} = 1;                                # Remember that we've seen it
                push(@config2, " ! GLOBAL NAT OBJECT:  $fld[$i]");
                foreach ( expand_object( @{$objects{$fld[$i]}} ) ) {    # Expand the object and output each element
                    push(@config2, " !   $_");
                }
            }
        }
        next LINE2;
    }

# Push all other lines onto the config array
#
    push(@config2, $_);
}

# Print the final config as part of the object substitution into access-lists.
# For each "access'list" line in the config, check to see if it contains an
# "object(-group)?" keyword and isn't a "remark", and if so call "&acl_obj_grp" to
# expand it with the corresponding items in the named object(-group)? (possibly
# recursively).  Any non-access-list lines are simply printed.
# After this, we're done!
#
foreach (@config2) {
    if (/^access-list.*\s+object(?:-group)?\s+/ && !/^access-list\s+\S+\s+remark/) {
        (my $tmp = $_) =~ s/(access-list\s+\S+)(.*)/$1 remark ORIGINAL:$2/;
        print "$tmp\n";
        acl_obj_grp($_);
    } else {
        print "$_\n";
    }
}

#####################################################################################
# Subroutine "get_line"
#
# Return the next input line in "$_", but replace any trailing white space (this will
# also "chomp" it), delete any Carriage Returns (Windows line endings), delete any
# "more" prompts and their associated white space that some terminal programs include,
# and skip any lines that have only white space or are empty after all the above.
#
sub get_line {
	while ( defined ($_ = <>) ) {
        chomp;
        s/\r//g;                # Remove any Carriage Return characters (Windows line endings).
        s/\s+$//;               # Remove any trailing white space.
        s/<--- More --->//i;    # Remove any "More" prompts that might be present.
        s/ {14}//;              # Remove the 14 spaces that often follow a "More" prompt, maybe on next line.
        last unless /^\s*$/;    # Get the next line if the current line is empty or only white space.
	}
	$_;
}


#####################################################################################
# Subroutine "acl_obj_grp"
#
# Replace the named "object-group" on the access-list line parameter with the
# corresponding items from the object group.  Because we were smart when we parsed
# the "object-group" definitions previously, we can do a simple replacement here.
# Note that this only works for "object-groups" (not simple "objects"), and only in
# "access-list" commands.  NAT commands are different, and are handled elsewhere...
#
sub acl_obj_grp {
    my ($ace) = @_;
    my $name = "";
    my $new_ace = "";
    my $h_acl = 0;
    my $h_service = 0;

    # We need the first ".*" below to be non-greedy, since there could be multiple object-groups
    # on a line and we need to match them in the same order here as when we replace them later.
    # The recursion-terminating case is when there is no "object(-group)?" string in "$ace", which
    # sets "$name" to nothing ("undef"), which we test for and if so, just print the final,
    # completely processed version of "$ace".
    #
    ($name) = $ace =~ /.*?object(?:-group)?\s+(\S+)/;

    if ($name) {
        foreach my $obj (@{$objects{$name}}) {
            if ($obj =~ /destination|source|icmp/) {    # Objects with src, dst, or icmp are ugly,
                                                        #  since we have to build them up part by part...
                $h_acl = parse_acl($ace);               # Parse the ACE and the object so we can get
                $h_service = parse_obj_service($obj);   #  the individual parts needed to build the final ACE.
                
                # We should probably do more error checking here, but we assume the config came from
                # a running ASA so the syntax should be correct.
                
                # Set any undefined fields to the empty string so we can just blindly build up the
                # final ACE with all the possible fields in the correct order.  We're assuming some
                # fields will absolutely be defined because the config came from a running ASA.
                # Also, we might get extra spaces in the final ACE, but we'll clean that up later.
                # Finally, we don't have to worry about the "svc_proto" service-objects because
                # they have only one field and don't allow source, destination, or ports, so they
                # get handled correctly elsewhere.
                #
                $h_acl->{user}        = "" if not defined $h_acl->{user};
                $h_acl->{securitys}   = "" if not defined $h_acl->{securitys};
                $h_acl->{securityd}   = "" if not defined $h_acl->{securityd};
                $h_acl->{ports}       = "" if not defined $h_acl->{ports};
                $h_acl->{options}     = "" if not defined $h_acl->{options};
                
                $h_service->{srv_tcpudp}      = ""  if not defined $h_service->{srv_tcpudp};
                $h_service->{srv_source}      = ""  if not defined $h_service->{srv_source};
                $h_service->{srv_destination} = ""  if not defined $h_service->{srv_destination};
                $h_service->{srv_icmp}        = ""  if not defined $h_service->{srv_icmp};
                $h_service->{srv_type_code}   = ""  if not defined $h_service->{srv_type_code};
                
                # The following blocks build up the new ACE from the components parsed above,
                # depending on which type of service was on the incoming ACE:
                #
                if ($h_service->{srv_icmp}) {
                    $new_ace = "access-list $h_acl->{name} extended "
                             . "$h_acl->{action} "
                             . "$h_service->{srv_icmp} "
                             . "$h_acl->{user} "
                             . "$h_acl->{securitys} "
                             . "$h_acl->{source} "
                             . "$h_acl->{securityd} "
                             . "$h_acl->{destination} "
                             . "$h_service->{srv_type_code} "
                             . "$h_acl->{options}";
                }
                
                if ($h_service->{srv_tcpudp} =~ /^(?:tcp|udp)$/) {
                    $new_ace = "access-list $h_acl->{name} extended "
                             . "$h_acl->{action} "
                             . "$h_service->{srv_tcpudp} "
                             . "$h_acl->{user} "
                             . "$h_acl->{securitys} "
                             . "$h_acl->{source} "
                             . "$h_service->{srv_source} "
                             . "$h_acl->{securityd} "
                             . "$h_acl->{destination} "
                             . "$h_service->{srv_destination} "
                             . "$h_acl->{options}";
                }
                
                if ($h_service->{srv_tcpudp} =~ /tcp-udp/) {            # For "tcp-udp" we need to build two ACE's
                    $new_ace = "access-list $h_acl->{name} extended "
                             . "$h_acl->{action} "
                             . "tcp "                                   #  One for "tcp"...
                             . "$h_acl->{user} "
                             . "$h_acl->{securitys} "
                             . "$h_acl->{source} "
                             . "$h_service->{srv_source} "
                             . "$h_acl->{securityd} "
                             . "$h_acl->{destination} "
                             . "$h_service->{srv_destination} "
                             . "$h_acl->{options}";
                             
                    $new_ace =~ s/\s\s+/ /g;        # Eliminate extra spaces in the new ACE,
                    acl_obj_grp($new_ace);              # and call "obj_group" here as a special case for "tcp" lines.
                             
                    $new_ace = "access-list $h_acl->{name} extended "
                             . "$h_acl->{action} "
                             . "udp "                                   #  ...and one for "udp".
                             . "$h_acl->{user} "
                             . "$h_acl->{securitys} "
                             . "$h_acl->{source} "
                             . "$h_service->{srv_source} "
                             . "$h_acl->{securityd} "
                             . "$h_acl->{destination} "
                             . "$h_service->{srv_destination} "
                             . "$h_acl->{options}";
                }
                
                $new_ace =~ s/\s\s+/ /g;        # Eliminate extra spaces in the new ACE.
            } else {
                ($new_ace = $ace) =~ s/^(.*?)object(?:-group)?\s+\S+(.*)$/$1$obj$2/;   # Need non-greedy ".*" here, too.
            }
            acl_obj_grp($new_ace);      # Recursive call to ourself to make sure we process all objects
        }
    } else {                # No more objects in the ACE, so we're done.
       print " $ace\n";     # Print a leading space on the line so it'll be more obvious in the final config.
    }
}


#####################################################################################
# Subroutine "parse_acl"
#
# Parse an ACL entry (ACE) into its individual components so we can be smart about
# replacing the appropriate parts when processing an "object-group service" object.
# These groups can contain protocol ("tcp" and "udp") keywords, as well as "source"
# and "destination" keywords, so we need to insert the specified services (i.e. port
# specifications) at the correct place in the new ACL entry.
#
# We are passed a single ACE and return a hash containing the named fields in that ACE.
# This will allow the caller to replace the correct fields based on the contents of the
# individual object being processed.
#
# If we can't parse the incoming ACE, just return a reference to an empty hash.
#
# Note: The bulk of the regex definitions used here and their formatting style came from a
# post by "CountZero" near the end this perlmonks.org discussion topic, which I modified
# to include the full ASA extended ACL syntax (as of ASA 9.2 code):
#
#   http://www.perlmonks.org/?node_id=906142
#
# Thanks, CountZero!
#
sub parse_acl {
    my ($ace) = @_;
    my %ace_hash = ();

    my $IPv4 = qr{  (?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})  }x;

    my $IPv6 = qr{  (?:[0-9a-fA-F:]*:[0-9a-fA-F:/]+)  }x;

    my $protocol = qr{  (?:object(?:-group)?\s+\S+|\S+)  }x;

    my $user = qr{
        (?:object-group-user\s+\S+)
      | (?:user(?:-group)\s+(?:any|none|(?:\S+\s+\\{1,2}\s+)?\S+))
    }x;

    my $security = qr{
        (?:object-group-security\s+\S+)
      | (?:security-group\s+(?:name|tag)\s+\S+)
    }x;

    my $network = qr{
        (?:host\s+$IPv4)
      | (?:$IPv4\s+$IPv4)
      | (?:$IPv6)
      | (?:any4|any6|any)
      | (?:object(?:-group)?\s+\S+)
      | (?:interface\s+\S+)
    }x;

    my $ports = qr{
        (?:(?:eq|gt|lt|neq)\s+\d+)
      | (?:range\s+\d+\s+\d+)
      | (?:object(?:-group)?\s+\S+)
    }x;

    my $acl_regex = qr{^
        access-list                      \s+ 
        (?<name>\S+)                     \s+   # name
        extended                         \s+ 
        (?<action>(?:permit|deny))       \s+   # action
        (?<proto>$protocol)              \s+   # protocol
        (?:(?<user>$user)\s+)?                 # user (optional)
        (?:(?<securitys>$security)\s+)?        # source security_group (optional)
        (?<source>$network)              \s+   # source_network
        (?:(?<securityd>$security)\s+)?        # destination security_group (optional)
        (?<destination>$network)               # destination_network
        (?:\s+(?<ports>$ports))?               # ports (optional)
        (?:\s+(?<options>.*))?                 # keywords at end of ACL (optional)
    }x;

    if ( $ace =~ /$acl_regex/ ) {
        $ace_hash{name}        = $+{name};
        $ace_hash{action}      = $+{action};
        $ace_hash{proto}       = $+{proto};
        $ace_hash{user}        = $+{user}         if defined $+{user};
        $ace_hash{securitys}   = $+{securitys}    if defined $+{securitys};
        $ace_hash{source}      = $+{source};
        $ace_hash{securityd}   = $+{securityd}    if defined $+{securityd};
        $ace_hash{destination} = $+{destination};
        $ace_hash{ports}       = $+{ports}        if defined $+{ports};
        $ace_hash{options}     = $+{options}      if defined $+{options};
    }

    return \%ace_hash;
}


#####################################################################################
# Subroutine "parse_obj_service"
#
# Parse a "service-object" defined in an "object-group service" object.
# These can define a source and/or destination, so we need to find them so we
# can build the final ACE with the fields in the correct position.
#
# If we can't parse the incoming service-object, just return a reference to an
# empty hash.
#
sub parse_obj_service {
    my ($ace) = @_;
    my %ace_hash = ();

    my $ports = qr{
        (?:(?:eq|gt|lt|neq)\s+\S+)
      | (?:range\s+\S+\s+\S+)
    }x;

    my $acl_obj_grp_srv_regex = qr{^
        ( (?<srv_tcpudp>(?:tcp-udp|tcp|udp))                     # tcp-udp service(s)
          ( \s+ source      \s+ (?<srv_source>$ports)      )?    # source (optional)
          ( \s+ destination \s+ (?<srv_destination>$ports) )? )  # destination (optional)
      | ( (?<srv_icmp>(?:icmp6|icmp))                            # icmp service
          (?:\s+(?<srv_type_code>\S+ (?:\s+\S+)? ) )? )          # icmp type [code] (optional)
      | (?<srv_proto>\S+)                                        # other protocol
    }x; 

    if ( $ace =~ /$acl_obj_grp_srv_regex/ ) {
        $ace_hash{srv_proto}       = $+{srv_proto}        if defined $+{srv_proto};
        $ace_hash{srv_tcpudp}      = $+{srv_tcpudp}       if defined $+{srv_tcpudp};
        $ace_hash{srv_source}      = $+{srv_source}       if defined $+{srv_source};
        $ace_hash{srv_destination} = $+{srv_destination}  if defined $+{srv_destination};
        $ace_hash{srv_icmp}        = $+{srv_icmp}         if defined $+{srv_icmp};
        $ace_hash{srv_type_code}   = $+{srv_type_code}    if defined $+{srv_type_code};
    }

    return \%ace_hash;
}


#####################################################################################
# Subroutine "expand_object"
#
# Recursively expand the passed-in array to include all nested sub-objects, returning
# the resulting array.
#
#
sub expand_object {
    my @copy = ();
    foreach (@_) {
        if (/^object\S*\s+/) {      # Sub-objects start with "object" or "object-group"
            (my $obj_name) = /^object\S*\s+(\S+)/;
            my @tmp = expand_object(@{$objects{$obj_name}});
            push(@copy, @tmp);
        } else {
            push(@copy, $_);
        }
    }
    return @copy;
}
