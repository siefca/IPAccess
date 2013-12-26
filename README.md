# IP Access Control for Ruby

[![Gem Version](https://badge.fury.io/rb/ipaccess.png)](http://badge.fury.io/rb/ipaccess)

**ipaccess version `1.2`** (`Mortal Compat`)

* https://rubygems.org/gems/ipaccess
* https://github.com/siefca/ipaccess
* http://rubydoc.info/gems/ipaccess/
* pw@gnu.org

## Description

This library provides classes for controlling IP access
in your programs. You can use it to build your own
routines for checking IP addresses against access lists
or simply use altered sockets implementation which is also
shipped with this library.

## Features

* Maintaining IP access lists based on rules; see [IPAccess::List](http://rubydoc.info/gems/ipaccess/IPAccess/List).
* Grouping input/output access lists into sets; see [IPAccess::Set](http://rubydoc.info/gems/ipaccess/IPAccess/Set).
* Automating access checks and raising exceptions; see [IPAccess::Set](http://rubydoc.info/gems/ipaccess/IPAccess/Set#check_in).
* Many formats of IP addresses accepted; see [IPAccess.to_cidrs](http://rubydoc.info/gems/ipaccess/IPAccess#to_cidrs-class_method).
* Variants of socket handling classes with IP access control; see [IPAccess::Socket](http://rubydoc.info/gems/ipaccess/IPAccess/Socket) and [IPAccess::Net](http://rubydoc.info/gems/ipaccess/IPAccess/Net).
* Methods for patching native socket handling classes; see [IPAccess.arm](http://rubydoc.info/gems/ipaccess/IPAccess#arm-class_method).
* Methods for patching single network objects; see [IPAccess.arm](http://rubydoc.info/gems/ipaccess/IPAccess#arm-class_method).
* Bases on the library [NetAddr](http://netaddr.rubyforge.org/) and uses trees to store data.

## What's in the bag?

There are two classes used to evaluate IP access:
`IPAccess::List` and `IPAccess::Set`.

First class maintains a list of rules and methods for checking whether
given IP matches them. Second class is more general – it throws exceptions and distinguishes between
incoming and outgoing IP traffic. That's because it maintains two access lists.

The classes described above do not interfere with any network classes and/or objects unless
you code them to do that. However, this library also provides special variants of socket handling
classes that use IPAccess::Set instances to control access of the real TCP/IP traffic in an easy way.

## Synopsis

Total control:

```ruby
require 'ipaccess/net/http'
require 'open-uri'

# Add host's IP by to black list of global output access set
IPAccess::Set::Global.output.blacklist 'example.org'

# Arm all future sockets used by Net::HTTP
IPAccess.arm Net::HTTP

# Open URI
open 'http://example.org/'
```

Access management for specific socket objects:

```ruby
# load patched sockets
require 'ipaccess/socket'

# assume IP given by untrusted user
ip_from_user = '192.168.5.5'

# create new access set
acl = IPAccess::Set.new

# blacklist private and local subnets
acl.output.block :private, :local

# create TCP socket with IP access control
socket = IPAccess::TCPSocket(ip_from_user, 80, acl)
```

## Requirements

* [netaddr](http://netaddr.rubyforge.org/)
* [rake](http://rake.rubyforge.org/)
* [rubygems](http://docs.rubygems.org/)

## Download

## Source code

* https://github.com/siefca/IPAccess
* `git clone git://github.com/siefca/IPAccess.git`

## Gem

* http://rubygems.org/gems/ipaccess

## Installation

* `gem install ipaccess`

## More information

See IPAccess module's [documentation](http://rubydoc.info/gems/ipaccess/) for more information.

## License

Copyright (c) 2009-2014 by Paweł Wilk.

IPAccess is copyrighted software owned by Paweł Wilk (pw@gnu.org).
You may redistribute and/or modify this software as long as you
comply with either the terms of the LGPL (see {file:docs/LGPL}),
or Ruby's license (see {file:docs/COPYING}).

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE.

