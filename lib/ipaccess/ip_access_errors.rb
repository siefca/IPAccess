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

  def initialize(addr, access_list=nil)
    @peer_ip = addr.native
    @access_list = access_list
  end
  
  # Shows error message.
  
  def message
    list_name = ""
    list_name = "#{@access_list.name} " unless (@access_list.nil? || @access_list.name.to_s.empty?)
    return "connection from #{@peer_ip.to_s} denied by #{list_name}access list"
  end
  
end

# This class handles IP access denied exceptions for incomming connections/datagrams.

class IPAccessDeniedIn < IPAccessDenied

  def message
    return "incomming " + super
  end

end

# This class handles IP access denied exceptions for outgoing connections/datagrams.

class IPAccessDeniedOut < IPAccessDenied

  def message
    return "outgoing" + super
  end
  
end

