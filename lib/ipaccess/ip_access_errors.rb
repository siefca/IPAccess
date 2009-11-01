# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# This file contains IPAccessDenied class
# used to report access denials by
# IPAccess::Set objects.
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


# This class handles IP access denied exceptions.
#
# === Example
# 
#   require 'ipaccess/sockets'
#   
#   begin
#   
#     IPAccess::Set::Global.input.blacklist :local, :private
#     s = IPAccess::TCPServer.new(31337)
#     s.opened_on_deny = true
#     
#     puts "\nnow use terminal and issue: telnet 127.0.0.1 31337\n"
#     n  = s.accept
#     
#   rescue IPAccessDenied => e
#     
#     puts "Message:\t#{e.message}"
#     puts
#     puts "ACL:\t\t#{e.acl}"
#     puts "Exception:\t#{e.inspect}"
#     puts "Remote IP:\t#{e.peer_ip}"
#     puts "Rule:\t\t#{e.rule}"
#     puts "Originator:\t#{e.originator}"
#     puts "CIDR's Origin:\t#{e.peer_ip.tag[:Originator]}\n\n"
#     
#     unless e.originator.closed?
#       e.originator.write("Access denied!!!\n\r\n\r")
#       e.originator.close
#     end
#   end
 
class IPAccessDenied < SecurityError
  
  # Object passed during raising an exception.
  # Usually a network object that is used
  # to communicate with a prohibited peer.

  attr_accessor :originator
  
  # Access list's rule that matched as
  # an NetAddr::CIDR object.
  
  attr_reader :rule
  
  # Remote address that caused an
  # exceotion to happend as an
  # NetAddr::CIDR object
  attr_reader :peer_ip
  
  # Access set that was used to check access.
  
  attr_reader :acl
  
  # Creates new object. First argument should be
  # a NetAddr::CIDR object containing address
  # of denied connection. Second argument should
  # be a CIDR rule that matched. Third argument
  # should be an IPAccess::Set object. Last
  # argument should be an object that will be
  # passed to exception as +object+ member –
  # usualy it should be set to object that caused
  # the exception to happend.
  
  def initialize(addr, rule=nil, acl=nil, obj=nil)
    @peer_ip    = addr
    @rule       = rule
    @acl        = acl
    @originator = obj
  end
  
  # Returns string representation of access set name rule.
  
  def set_desc
    if (@acl.is_a?(IPAccess::Set) && !@acl.name.to_s.empty?)
      @acl.name.to_s + " "
    elsif @acl.is_a?(String)
      @acl + " "
    else
      ""
    end
  end
  
  # Returns string representation of rule.
  
  def rule_desc
    if @rule.is_a?(NetAddr::CIDR)
      if @rule.version == 6
        rule = @rule.to_s(:Short => true)
        rule = ":#{rule}" if rule =~ /^\//
      else
        rule = @rule.to_s
      end
      return "rule: #{rule}"
    elsif @rule.is_a?(String)
      return "rule: #{@rule}"
    else
      return "rule"
    end
  end
  
  # Returns string representation of address.
  
  def addr_desc
    if @peer_ip.is_a?(NetAddr::CIDR)
      if @peer_ip.version == 6
        if @peer_ip.to_i(:netmask) == ((2**128)-1)
          return @peer_ip.ip(:Short => true)
        else
          pip = @peer_ip.to_s(:Short => true)
          pip = ":#{pip}" if pip =~ /^\//
          return pip
        end
      else
        if @peer_ip.to_i(:netmask) == 4294967295
          return @peer_ip.ip
        else
          return @peer_ip.to_s
        end
      end
    elsif @peer_ip.is_a?(String)
      return @peer_ip
    else
      return @peer_ip.to_s
    end
  end
  
  # Returns an error message.
  
  def message
    return "connection with #{addr_desc} " +
            "denied by #{set_desc}#{rule_desc}"
  end
  
  # Returns the result of calling addr_desc.
  
  def to_s
    addr_desc
  end
  
end

# This class handles IP access denied exceptions
# for incoming connections/datagrams.

class IPAccessDenied::Input < IPAccessDenied

  def message
    return "incoming connection from "  +
           "#{addr_desc} denied by "    +
           "#{set_desc}#{rule_desc}"
  end

end

# This class handles IP access denied exceptions
# for outgoing connections/datagrams.

class IPAccessDenied::Output < IPAccessDenied

  def message
    return "outgoing connection to "  +
           "#{addr_desc} denied by "  +
           "#{set_desc}#{rule_desc}"
  end
  
end

