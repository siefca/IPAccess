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
# used to control IP access. There are
# three major components you may need:
# 
# === IPAccess::List class
# 
# This class lets you create IP
# access list with blacklisted
# and whitelisted elements. It
# also has methods for checking
# whether given IP matches the
# list.
# 
# === IPAccess::Set class
# 
# This class contains two
# objects that are instances
# of IPAccess::List class.
# It allows you to create so
# called access set. The access
# set contains members named
# +input+ and +output+. All methods
# that validate IP access do it
# against one of the lists. Input
# access list is for incomming
# and output for outgoing IP traffic.
# In case of connection-oriented
# sockets and other network objects
# the convention is to use output access
# list to validate connections that
# we initiate. The incomming traffic
# in that model means the connections
# initiated by a remote peer.
# 
# === Patching engine
# 
# IPAccess was initialy considered as a
# set of classes that you may use
# in your own programs to control
# IP access. That means your own classes
# used for communication should use
# access lists or sets before making any
# real connections or sending any datagrams.
# 
# Fortunately there are many network classes,
# including sockets, that Ruby ships with.
# It would be waste of resources to not modify
# them to support IP access control and automagically
# throw exceptions when access should be denied.
# 
# And here the special module method called +IPAccess.arm+
# comes in. It lets you patch most of Ruby's
# networking classes and objects. Besides
# equipping them in IPAccess::Set instance
# it also adds some methods for doing quick
# checks and changes in access lists.
# 
# The patching engine can arm network classes and
# single network objects. It is not loaded by default
# since you may not want extra code attached to a
# program that uses access lists or sets with
# own access checking code.
# 
# === Variants of popular classes
# 
# Sometimes you want to write a code that
# uses standard Ruby's network objects
# but you find it dirty to alter classes or objects.
# In that case you may want to use static variants
# of Ruby's network classes that are not patches
# but derived classes.
# 
# === Exceptions
# 
# When you are dealing with patched (armed) versions
# of classes and objects or when you are using
# special variants of popular network classes, you have
# to rely on exceptions as the only way for
# access checking methods to tell your program
# that an event (like access denied) happened.
# 
# Note that when exception is thrown
# the communication session is closed in case
# of connection-oriented network objects.
# You may change it by switching +close_on_deny+
# attribute to +false+.
# 
# === Sockets in armed network objects
# 
# Specialized Ruby's network classes,
# such as Net::HTTP or Net::Telnet
# and their variants created by this library,
# make use of socket objects. For example
# Net::HTTP class uses TCPSocket instance to
# create TCP connection. When versions
# of these <tt>Net::</tt> objects with
# enabled access control are used then
# the internal routines of IPAccess
# will also try to patch underlying sockets and assign
# to them the same access set that is used by main
# object. It is done to avoid access leaks.
# However, such armed internal sockets will have
# +close_on_deny+ flag switched off since
# closing session should be settled
# by main object.
# 
# === Ordination of elements
# 
# To properly understand what are the most important
# structures mentioned above it's worth
# to look at the diagram:
# 
# link:images/ipaccess_view.png
#  
# == Usage
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
# === Structures
# 
# IP addresses used by the classes are internaly and interfacialy
# represented by NetAddr::CIDR[http://netaddr.rubyforge.org/classes/NetAddr/CIDR.html]
# objects (NetAddr::CIDRv4[http://netaddr.rubyforge.org/classes/NetAddr/CIDRv4.html] and
# NetAddr::CIDRv6[http://netaddr.rubyforge.org/classes/NetAddr/CIDRv6.html]). Due to
# performance reasons any access list internally is represented as a tree
# (NetAddr::Tree[http://netaddr.rubyforge.org/classes/NetAddr/Tree.html])
# with special tags assigning rules to virtual lists.
# 
# === Relations
# 
# Here is a diagram which shows relations
# between the IPAccess::TCPSocket class
# and other classes from this module:
# 
# link:images/ipaccess_relations.png

module IPAccess
end
