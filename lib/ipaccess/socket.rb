# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Classes contained in this file are subclasses
# of Ruby socket handling classes equipped
# with IP access control.
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
# 
# See ipaccess/ghost_doc.rb for documentation of this classes.
# 
#++

require 'socket'
require 'ipaccess/ip_access'
require 'ipaccess/ip_access_patches'


class IPAccess::Socket < Socket
  include IPAccess::Patches::Socket
end

class IPAccess::UDPSocket < UDPSocket
  include IPAccess::Patches::UDPSocket
end

if Object.const_defined?(:SOCKSSocket)
  class IPAccess::SOCKSSocket < SOCKSSocket
    include IPAccess::Patches::SOCKSSocket
  end
end

class IPAccess::TCPSocket < TCPSocket
  include IPAccess::Patches::TCPSocket
end

class IPAccess::TCPServer < TCPServer
  include IPAccess::Patches::TCPServer
end
