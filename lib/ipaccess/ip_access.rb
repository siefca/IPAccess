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

class IPAccess
  
  # This is the list that keeps IPAccessList object that keeps information
  # about blocked IP addresses.
  attr_accessor :blacklist
  
  # This is the IPAccessList object for creating exceptions from black list.
  attr_accessor :whitelist
    
  # This method creates new IPAccess object.
  
  def initialize
    @whitelist = IPAccessList.new
    @blacklist = IPAccessList.new
    return self
  end
  
  # Returns +true+ if access is denied and +false+ otherwise.
  # Access is denied if black list contains one of the addresses
  # and white list doesn't contain it. If access is denied for
  # at least one of the passed elements this method returns +true+.
  
  def denied?(*addrs)
    addrs = @blacklist.obj_to_ip6(*addrs)
    addrs.each do |addr|
      return true if (@blacklist.include?(addr) && !@whitelist.include?(addr))
    end
    return false
  end
  
  # This method returns +true+ if access may be granted to all
  # of the given objects. Otherwise it returns +false+.
  # It has opposite behaviour to method denied?
  
  def granted?(*addrs)
    not denied?(*addrs)
  end
  
  # This method is an alias for IPAccessList#add on whitelist.

  def grant(*addrs)
    @whitelist.add(*addrs)
  end
  
  # This method is an alias for IPAccessList#add on blacklist.
  
  def deny(*addrs)
    @blacklist.add(*addrs)
  end

end

