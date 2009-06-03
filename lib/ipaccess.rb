# :stopdoc:
# encoding: utf-8
# :startdoc:
#
# == Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of GNU Lesser General Public License or Ruby License.
# 
# Classes contained in this library allow you to create
# and manage IP access lists in an easy way. You may use
# IPAccess class to maintain black list and white list
# and validate connections against it. You also may use
# IPAccessList class directly to build your own lists.

require 'rubygems'
require 'socket'
require 'resolv'
require 'netaddr'

require 'ipaccess/netaddr_patch'
require 'ipaccess/ip_access_list'
require 'ipaccess/ip_access'
require 'ipaccess/sockets'

