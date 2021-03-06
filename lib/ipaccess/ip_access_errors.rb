# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009-2014 by Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL.html] or {Ruby License}[link:docs/COPYING.html].
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
#     puts "Remote IP:\t#{e.peer_ip} (#{e.peer_ip_short})"
#     puts "Rule:\t\t#{e.rule} (#{e.rule_short})"
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
  
  # Socket object associated with
  # an exception. Only few checks
  # sets it.
  
  attr_reader :socket
  
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
  
  def initialize(addr, rule=nil, acl=nil, obj=nil, socket=nil)
    @peer_ip    = addr
    @rule       = rule
    @acl        = acl
    @originator = obj
    @socket     = socket
  end
  
  # Returns string representation of access set name rule.
  
  def access_set
    if (@acl.is_a?(IPAccess::Set) && !@acl.name.to_s.empty?)
      @acl.name.to_s
    elsif @acl.is_a?(String)
      @acl
    else
      ""
    end
  end
  
  # Returns string representation of access set name rule.
  
  def access_set_desc
    as = self.access_set
    as.empty? ? "" : as + " "
  end
  protected :access_set_desc
  
  # Returns string representation of a rule
  # in short version.
  
  def rule_short
    if @rule.is_a?(NetAddr::CIDR)
      if @rule.version == 6
        rule = @rule.to_s(:Short => true)
        rule = "::#{rule}" if rule =~ /^\//
        rule = ":#{rule}" if rule =~ /^:[^:]/
      else
        rule = @rule.to_s
      end
      return rule
    elsif @rule.is_a?(String)
      return @rule
    else
      return ""
    end
  end

  # Returns string representation of a rule
  # with prefix.
  
  def rule_desc
    rs = self.rule_short
    rs.empty? ? "rule" : "rule: #{rs}"
  end
  protected :rule_desc
  
  # Returns string representation of an IP address
  # in short version.
  
  def peer_ip_short
    if @peer_ip.is_a?(NetAddr::CIDR)
      if @peer_ip.version == 6
        pip = @peer_ip.to_s(:Short => true)
        pip = "::#{pip}" if pip =~ /^\//
        pip = ":#{pip}" if pip =~ /^:[^:]/
        pip = pip.split('/').first if pip =~ /\/128$/
        return pip
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
  
  # Returns a string representing a reason
  # of adding to a black list or +nil+
  # if there was no reason given.
  
  def reason
    return nil unless (rule.respond_to?(:tag) && rule.tag.respond_to?(:has_key?))
    r = rule.tag[:Reason_black]
    return r.nil? ? r : r.to_s
  end
  
  # This returns reason but will return
  # an empty string instead of +nil+
  # if something will go wrong. It will
  # wrap the text in braces.
  
  def reason_desc
    reason.nil? ? "" : " (#{reason})"
  end
  protected :reason_desc
  
  # Returns an error message.
  
  def message
    return "connection with #{peer_ip_short} "  +
            "denied by #{access_set_desc}#{rule_desc}" +
            "#{reason_desc}"
  end
  
  # This method returns a string containing
  # all important attributes of an exception.
  
  def show
    "Message:\t#{self.message}\n\n"                           +
    "ACL:\t\t#{self.acl}\n"                                   +
    "Exception:\t#{self.inspect}\n"                           +
    "Remote IP:\t#{self.peer_ip} (#{self.peer_ip_short})\n"   +
    "Rule:\t\t#{self.rule} (#{self.rule_short})\n"            +
    "Originator:\t#{self.originator}\n"                       +
    "CIDR's Origin:\t#{self.peer_ip.tag[:Originator]}\n\n"
  end
  
  # Returns the result of calling peer_ip_short.
  
  def to_s
    peer_ip_short
  end
    
end

# This class handles IP access denied exceptions
# for incoming connections/datagrams.

class IPAccessDenied::Input < IPAccessDenied

  def message
    return "incoming connection from "      +
           "#{peer_ip_short} denied by "    +
           "#{access_set_desc}#{rule_desc}" +
           "#{reason_desc}"
  end

end

# This class handles IP access denied exceptions
# for outgoing connections/datagrams.

class IPAccessDenied::Output < IPAccessDenied

  def message
    return "outgoing connection to "        +
           "#{peer_ip_short} denied by "    +
           "#{access_set_desc}#{rule_desc}" +
           "#{reason_desc}"
  end
  
end

# This class handles multiple IP access denied
# exception and behaves like a enumerable collection.
# It is used to collect and throw many errors
# at once.

class IPAccessDenied::Aggregate < SecurityError
  instance_methods.each { |m| undef_method m unless m =~ /(^__|^send$|^object_id$|^class$)/ }
  
  def method_missing(name, *args, &block)
    target.send(name, *args, &block)
  end
  protected :method_missing

  def target
    @target ||= []
  end
  protected :target
  
  def message
    "some connections reported access denied"
  end
  
end
