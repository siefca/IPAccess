# encoding: utf-8
#
# Easy to manage and fast IP access lists.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   LGPL
# 
# Classes contained in this library allow you to create
# and manage IP access lists in an easy way. You may use
# IPAccess class to maintain black list and white list
# and validate connections against it. You also may use
# IPAccessList class directly to build your own lists.
#
# The classes use NetAddr::CIDR objects to store IP
# addresses/masks and NetAddr::Tree to maintain
# access lists.

# This class handles IP access denied exceptions.
 
class IPAccessDenied < Errno::EACCES

  # Creates new object. First argument should be a NetAddr::CIDR
  # object containing address of denied connection.
  # Second argument should be a CIDR rule that matched.
  # Last argument should be an IPAccess object.

  def initialize(addr, rule=nil, access_list=nil)
    @peer_ip = addr
    @access_list = access_list
    @rule = rule
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
    if @rule.is_a?(IPAddr)
      " rule: #{@rule.native.inspect.split[1].chomp('>')[5..-1]}"
    else
      ""
    end
  end
    
  # Shows an error message.
  
  def message
    return "connection with #{@peer_ip.to_s} denied by #{list_desc}access list#{rule_desc}"
  end
  
end

# This class handles IP access denied exceptions for incomming connections/datagrams.

class IPAccessDenied::Input < IPAccessDenied

  def message
    return "incomming connection from #{@peer_ip.to_s} denied by #{list_desc}access list#{rule_desc}"
  end

end

# This class handles IP access denied exceptions for outgoing connections/datagrams.

class IPAccessDenied::Output < IPAccessDenied

  def message
    return "outgoing connection to #{@peer_ip.to_s} denied by #{list_desc}access list#{rule_desc}"
  end
  
end

