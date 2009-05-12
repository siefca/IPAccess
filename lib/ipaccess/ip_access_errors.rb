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
# The classes use IPAddr objects to store data and IPAddrList
# to create lists with binary search capabilities.

# This class creates two lists, black and white, in order
# manage IP access.

# This class handles IP access denied exceptions.
 
class IPAccessDenied < Errno::EACCES

  # Creates new object. First argument should be an IPAddr
  # object containing address of denied connection.
  # Second argument should be an access list object.

  def initialize(addr, access_list=nil, rule=nil)
    @peer_ip = addr.native
    @access_list = access_list
    @rule = rule
  end
  
  # Shows error message.
  
  def message
    list_name = ""
    rule = ""
    list_name = "#{@access_list.name} " if (@access_list.is_a?(IPAccess) && !@access_list.name.to_s.empty?)
    rule = ", rule: #{@rule.native.inspect.split[1].chomp('>')[5..-1]}" if @rule.is_a?(IPAddr)
    return "connection from #{@peer_ip.to_s} denied by #{list_name}access list#{rule}"
  end
  
end

# This class handles IP access denied exceptions for incomming connections/datagrams.

class IPAccessDenied::Input < IPAccessDenied

  def message
    return "incomming " + super
  end

end

# This class handles IP access denied exceptions for outgoing connections/datagrams.

class IPAccessDenied::Output < IPAccessDenied

  def message
    return "outgoing" + super
  end
  
end

