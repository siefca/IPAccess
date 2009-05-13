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

require 'netaddr'

# This module contains few new methods extending
# original.

module NetAddr
  
  class CDIR
  
    # Returns +true+ if the IP address is an IPv4-mapped IPv6 address.

    def ipv4_mapped?
      return @version == 6 && (@ip >> 32) == 0xffff
    end

    # Returns +true+ if the IP address is an IPv4-compatible IPv6 address.

    def ipv4_compat?(addr)
      return false if @version != 6
      return false if (@ip >> 32) != 0
      a = (@ip & 0xffffffff)
      return (a != 0 && a != 1)
    end

    # Returns +true+ if the IP address is an IPv4-compatible or
    # IPv4-mapped IPv6 address.

    def ipv4_compliant?
      return false if @version != 6
      a = (@ip >> 32)
      return (a == 0xffff) if a.nonzero?
      a = (@ip & 0xffffffff)
      return (a != 0 && a != 1)
    end

  end # class CIDR
  
  class CIDRv4
      
    # Returns a new NetAddr::CIDRv6 object built by converting
    # the native IPv4 address to an IPv4-mapped IPv6 address.
    # Mask is also converted.
    
    def ipv4_mapped 
      return NetAddr::CIDR.create(@ip | 0xffff00000000,
                                  :Mask => @netmask << 96,
                                  :Version => 6)
    end

    # Returns a new NetAddr::CIDRv6 object built by converting
    # the native IPv4 address to an IPv4-compatible IPv6 address.
    # Mask is also converted.
    
    def ipv4_compat
      return NetAddr::CIDR.create(@ip,
                                  :Mask => @netmask << 96,
                                  :Version => 6)
    end
    
  end # class CIDRv4

  class CIDRv6
  
    def ipv4
      unless ipv4_compliant?
        raise VersionError, "Attempted to create version 4 CIDR " +
                             "with non-compliant CIDR item in version #{@version}."
      end
      return NetAddr::CIDR.create(@ip,
                                  :Mask => @netmask >> 96,
                                  :Version => 4)
    end
  
  end # class CIDRv4

end # module NetAddr

