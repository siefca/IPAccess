# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009-2014 by Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Classes contained in this file are subclasses
# of Ruby socket handling classes equipped
# with IP access control.
#

require 'socket'
require 'ipaccess/ip_access_set'
require 'ipaccess/patches/sockets'

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
