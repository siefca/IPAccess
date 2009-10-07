# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Classes contained in this library allow you to create
# and manage IP access lists in an easy way. You may use
# IPAccess::Set class to maintain inpu/output traffic control.
# You also may use IPAccess::List class directly to build
# your own access sets based on black lists and white lists.
# 
#--
# 
# Copyright (C) 2009 by Paweł Wilk. All Rights Reserved.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version; or 2) Ruby's License.
# 
# See the file COPYING for complete licensing information.
#
#++

require 'rubygems'
require 'socket'
require 'resolv'
require 'netaddr'

require 'ipaccess/patches/netaddr'
require 'ipaccess/ip_access_list'
require 'ipaccess/ip_access_set'

# This module contains classes that are
# used to control IP access. To properly
# understand what they are doing it's worth
# to see diagram presenting most important
# relations:
# 
# link:images/ipaccess_view.png
# 
# === Handling access sets and access lists
# 
# If you need just IP access lists that you will handle in your own way
# you may want to use two classes:
# 
# * IPAccess::Set to maintain access sets (containing input and output access lists),
# * IPAccess::List to maintain single access list.
# 
# === Using socket classes
# 
# If you want standard sockets to have access control enabled
# you may want to use:
# 
# * IPAccess::Socket (or issue <tt>IPAccess.arm Socket</tt>)
# * IPAccess::TCPSocket (or issue <tt>IPAccess.arm TCPSocket</tt>)
# * IPAccess::UDPSocket (or issue <tt>IPAccess.arm UDPSocket</tt>)
# * IPAccess::SOCKSocket (or issue <tt>IPAccess.arm SOCKSocket</tt>)
# * IPAccess::TCPServer (or issue <tt>IPAccess.arm TCPServer</tt>)
# 
# Before using any of them you must issue:
# 
# * <tt>require 'ipaccess/socket'</tt>
# 
# Using the IPAccess.arm causes standard socket class to be altered,
# while \IPAccess:: classes are just new variants of socket
# handling classes.
# 
# ==== Using other supported network classes
# 
# If you want some working objects to have access control enabled
# you may want to use:
# 
# * IPAccess::Net::Telnet (or issue <tt>IPAccess.arm Net::Telnet</tt>)
# * IPAccess::Net::HTTP (or issue <tt>IPAccess.arm Net::HTTP</tt>)
# * IPAccess::Net::FTP (or issue <tt>IPAccess.arm Net::FTP</tt>)
# * IPAccess::Net::POP3 (or issue <tt>IPAccess.arm Net::POP3</tt>)
# * IPAccess::Net::IMAP (or issue <tt>IPAccess.arm Net::IMAP</tt>)
# * IPAccess::Net::SMTP (or issue <tt>IPAccess.arm Net::SMTP</tt>)
# 
# ==== Using single network objects
# 
# If you want to enable access control for single network
# object from the list shown above you may issue:
# 
# 	require 'ipaccess/net/http'
# 	obj = Net::HTTP.new(host, port)
# 	IPAccess.arm obj
# 
# or
# 
# 	require 'ipaccess/socket'
# 	socket = IPAccess::TCPServer.new(31337)
# 	IPAccess.arm socket
# 	
# ..and so on.
# 
# === Note about internal structures
# 
# IP addresses used by the classes are internaly and interfacialy
# represented by NetAddr::CIDR[http://netaddr.rubyforge.org/classes/NetAddr/CIDR.html]
# objects (NetAddr::CIDRv4[http://netaddr.rubyforge.org/classes/NetAddr/CIDRv4.html] and
# NetAddr::CIDRv6[http://netaddr.rubyforge.org/classes/NetAddr/CIDRv6.html]). Due to
# performance reasons any access list internally is represented as a tree
# (NetAddr::Tree[http://netaddr.rubyforge.org/classes/NetAddr/Tree.html])
# with special tags assigning rules to virtual lists.
# 
# 

module IPAccess
end
