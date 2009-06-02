# encoding: utf-8
#
# Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This is licensed under LGPL or Ruby License.
# 
# === sockets
# 
# Classes contained in this file are subclasses
# of Ruby socket handling classes equipped
# with IP access control.

$LOAD_PATH.unshift '..'

require 'socket'
require 'ipaccess'
require 'ipaccess/ip_access_patches'

# Socket class with IP access control.
# It uses input access lists.

class IPAccess::Socket < Socket
  include IPAccess::Patches::Socket
end

# UDPSocket class with IP access control.
# It uses input access lists.

class IPAccess::UDPSocket < UDPSocket
  include IPAccess::Patches::UDPSocket
end

if Object.const_defined?(:SOCKSSocket)
  # SOCKSSocket class with IP access control.
  # It uses input access lists.
  class IPAccess::SOCKSSocket < SOCKSSocket
    include IPAccess::Patches::SOCKSSocket
  end
end

# TCPSocket class with IP access control.
# It uses output access lists.

class IPAccess::TCPSocket < TCPSocket
  include IPAccess::Patches::TCPSocket
end

# TCPServer class with IP access control.
# It uses input access lists.

class IPAccess::TCPServer < TCPServer
  include IPAccess::Patches::TCPServer
end

class IPAccess
  
  # This is special method that patches Ruby's standard
  # library socket handling classes and enables
  # IP access control for them.
  # Instances of such altered classes will be
  # equipped with member called +acl+ which
  # is a kind of IPAccess and allows you to
  # manipulate access rules.
  #
  # Passed argument may be class object,
  # string representation of class object
  # or symbol representing a class object.
  # 
  # Currently supported classes are:
  # +Socket+, +UDPSocket+, +SOCKSSocket+,
  # +TCPSocket+ and +TCPServer+.
  # 
  # Example:
  # 
  #     IPAccess.arm TCPSocket                            # arm TCPSocket class  
  #     IPAccess::Global.input.blacklist 'randomseed.pl'  # add randomseed.pl to global black list
  #     TCPSocket.new('randomseed.pl', 80)                # try to connect
  
  def self.arm(klass)
    klass = klass.name if klass.is_a?(Class)
    klass = klass.to_sym
    case klass
    when :Socket, :UDPSocket, :SOCKSSocket, :TCPSocket, :TCPServer
      
      klass.__send__(:include, IPAccess::Patches::klass)
    else
      raise ArgumentError, ""
    end
  end

end

IPAccess.arm Socket

#TCPSocket.__send__(:include, Kernel.const_get(:"IPAccess::Patches::TCPSocket"))



