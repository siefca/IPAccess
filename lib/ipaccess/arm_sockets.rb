# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# By requiring this file you are able to
# enable IP access control for all
# standard Ruby sockets.
#
# This file is loaded and executed
# when +IPAccess.arm(:sockets)+ is called.
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

require 'socket'
require 'ipaccess/ip_access_set'
require 'ipaccess/patches/sockets'

IPAccess.arm Socket
IPAccess.arm UDPSocket
IPAccess.arm TCPSocket
IPAccess.arm TCPServer
IPAccess.arm SOCKSSocket if Object.const_defined?(:SOCKSSocket)

