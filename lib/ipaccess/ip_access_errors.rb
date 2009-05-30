# encoding: utf-8
# 
# Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   LGPL
# 
# === ip_access_errors
# 
# This file contains IPAccessDenied class
# used to report access denials by
# IPAccess objects.

# This class handles IP access denied exceptions.
 
class IPAccessDenied < Errno::EACCES

  # Creates new object. First argument should be
  # a NetAddr::CIDR object containing address
  # of denied connection. Second argument should
  # be a CIDR rule that matched. Last argument
  # should be an IPAccess object.

  def initialize(addr, rule=nil, access_list=nil)
    @peer_ip = addr
    @rule = rule
    @access_list = access_list
  end
  
  # Returns string representation of access list name rule.
  
  def list_desc
    if (@access_list.is_a?(IPAccess) && !@access_list.name.to_s.empty?)
      "#{@access_list.name} "
    elsif @access_list.is_a?(String)
      "#{@access_list} "
    else
      ""
    end
  end
  
  # Returns string representation of rule.
  
  def rule_desc
    if @rule.is_a?(NetAddr::CIDR)
      if @rule.version == 6
        rule = @rule.to_s(:Short => true)
        rule = "::#{rule}" if rule =~ /^\//
      else
        rule = @rule.to_s
      end
      return " rule: #{rule}"
    elsif @rule.is_a?(String)
      return " rule: #{@rule}"
    else
      return ""
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
          pip = "::#{pip}" if pip =~ /^\//
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
  
  # Shows an error message.
  
  def message
    return "connection with #{addr_desc} " +
            "denied by #{list_desc}#{rule_desc}"
  end
  
end

# This class handles IP access denied exceptions
# for incoming connections/datagrams.

class IPAccessDenied::Input < IPAccessDenied

  def message
    return "incoming connection from "  +
           "#{addr_desc} denied by "    +
           "#{list_desc}#{rule_desc}"
  end

end

# This class handles IP access denied exceptions
# for outgoing connections/datagrams.

class IPAccessDenied::Output < IPAccessDenied

  def message
    return "outgoing connection to "  +
           "#{addr_desc} denied by "  +
           "#{list_desc}#{rule_desc}"
  end
  
end

