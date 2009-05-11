# encoding: utf-8
# 
# Easy to manage and fast IP access lists.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   LGPL
# 
# Classes contained in this library allows you to create and manage
# IP access lists in an easy way. You may use IPAccess class to maintain
# black list and white list and validate connections against it. You
# also may use IPAccessList class directly to build your own lists.
# 
# This classes use IPAddr objects to store data, IPAddrList class to
# create lists with binary search capabilities and Resolv class to
# map names to IP addresses if there is a need.

require 'ipaddr'
require 'socket'
require 'resolv'
require 'ipaddr_list'

require 'ip_access/ip_access_list'
