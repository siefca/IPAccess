# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009-2014 by Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Classes contained in this library allow you to create
# and manage IP access lists in an easy way. You may use
# IPAccess::Set class to maintain inpu/output traffic control.
# You also may use IPAccess::List class directly to build
# your own access sets based on black lists and white lists.

require 'rubygems'
require 'socket'
require 'resolv'
require 'netaddr'

require 'ipaccess/core'



