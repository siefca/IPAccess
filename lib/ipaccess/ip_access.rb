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

$LOAD_PATH.unshift '..'

require 'ipaddr_list'
require 'ipaccess/ip_access_list'

# This class creates two lists, black and white, in order
# manage IP access.

class IPAccess
  
  # This is the list that keeps IPAccessList object that keeps information
  # about blocked IP addresses.
  
  attr_accessor :blacklist
  
  # This is the IPAccessList object for creating exceptions from black list.
  
  attr_accessor :whitelist
  
  # Descriptive name of this object. Used in error reporting.
  
  attr_accessor :name
  
  # This method creates new IPAccess object.
  
  def initialize(blacklist=[], whitelist=[])
    @name = nil
    @blacklist = IPAccessList.new(blacklist)
    @whitelist = IPAccessList.new(whitelist)
    return self
  end
  
  # Returns matching IPAddr rule if access is denied and +false+ otherwise.
  # Access is denied if black list contains one of the addresses
  # and white list doesn't contain it. If access is denied for
  # at least one of the passed elements this method returns +true+.
  
  def denied_one?(*addrs)
    return false if @blacklist.empty?
    addrs = @blacklist.obj_to_ip6(*addrs)
    addrs.each do |addr|
      rule = @blacklist.include_ipaddr6?(addr)
      return rule if (rule && !@whitelist.include_ipaddr6?(addr))
    end
    return false
  end
  
  # Returns matching IPAddr rule if access is denied and +false+ otherwise.
  # Access is denied if black list contains the address
  # and white list doesn't contain it.
  
  def denied?(addr)
    return false if @blacklist.empty?
    addrs = @blacklist.obj_to_ip6(*addr).first
    addrs.each do |addr|
      rule = @blacklist.include_ipaddr6?(addr)
      return rule if (rule && !@whitelist.include_ipaddr6?(addr))
    end
    return false
  end
  
  # Returns matching IPAddr rule if access is denied and +false+ otherwise.
  # Access is denied if black list contains the IP address
  # from passed IPv6 IPAddr object and white list doesn't contain it.
  
  def ipaddr6_denied?(addr)
    return false if @blacklist.empty?
    rule = @blacklist.include_ipaddr6?(addr)
    return rule if (rule && !@whitelist.include_ipaddr6?(addr))
    return false
  end
  
  # This method returns +true+ if access may be granted to all
  # of the given objects. Otherwise it returns +false+.
  # It has opposite behaviour to method denied_all?
  
  def granted_all?(*addrs)
    not denied_one?(*addrs)
  end

  # This method returns +true+ if access may be granted to IP
  # obtained from the given objects. Otherwise it returns +false+.
  # It has opposite behaviour to method denied?
  
  def granted?(addr)
    not denied?(addr)
  end
  
  # This method returns +true+ if access may be granted to IPv6 address
  # from the given IPAddr object. Otherwise it returns +false+.
  # It has opposite behaviour to method ipaddr6_denied?
  
  def ipaddr6_granted?(addr)
    not ipaddr6_denied?(addr)
  end
  
  # This method is an alias for IPAccessList#add on whitelist.

  def grant(*addrs)
    @whitelist.add(*addrs)
  end
  
  alias_method :allow, :grant
  
  # This method is an alias for IPAccessList#add on blacklist.
  
  def deny(*addrs)
    @blacklist.add(*addrs)
  end
  
  # This method returns +true+ if blacklist is empty.
  def empty?
    @blacklist.empty?
  end
  
end


