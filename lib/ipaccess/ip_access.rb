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
require 'ipaccess/ip_access_errors'

# This class creates two lists, black and white, in order
# manage IP access.

class IPAccess
  
  # This is the list that keeps IPAccessList object that keeps information
  # about blocked IP addresses.
  
  attr_reader   :blacklist
  
  # This is the IPAccessList object for creating exceptions from black list.
  
  attr_reader   :whitelist
  
  # Descriptive name of this object. Used in error reporting.
  
  attr_accessor :name
  
  # Default exception class, which is based on IPAccessDenied.
  
  attr_reader   :default_exception
  
  # This method creates new IPAccess object. It optionally takes
  # two arrays of IPAddr objects (initial data for black list and white list)
  # and default_exception which should be class name used to raise exceptions.
  # This argument should be subclass of IPAccessDenied or symbol containg its name.
  # 
  # If the only argument is a class it is assumed that this is default exception
  # class and b&w lists are initially empty.
  
  def initialize(blacklist=nil, whitelist=nil, default_exception=nil)
    @name = nil
    if (blacklist.is_a?(Class) && whitelist.nil? && default_exception.nil?)
      default_exception = blacklist
      blacklist = nil
    end
    self.default_exception = (default_exception or IPAccessDenied)
    @blacklist = IPAccessList.new(blacklist)
    @whitelist = IPAccessList.new(whitelist)
    return self
  end
  
  # This method sets default exception class and ensures that the class is
  # based on IPAccessDenied.
  
  def default_exception=(name)
    unless name.respond_to?(:superclass)
      name = name.respond_to?(:to_sym) ? name.to_sym : name.to_s.to_sym
      if Kernel.const_defined?(name)
        name = Kernel.const_get(name)  # Fixme for ::
      else
        raise ArgumentError.new("default exception class #{name} doesn't exists")
      end
    end
    unless name.ancestors.grep(Class).include?(IPAccessDenied)
      raise ArgumentError.new("default exception class #{name} is not based on IPAccessDenied")
    end
    @default_exception = name
  end
  
  # Raises default exception including remote address and rule object.
  # Both arguments should be IPAddr objects but if the aren't they will be
  # converted – resistance is futile.
  
  def scream!(peer_ip=nil, rule=nil)
    peer_ip = @blacklist.obj_to_ip6(peer_ip) unless (peer_ip.to_s.empty? || peer_ip.is_a?(IPAddr))
    rule = @blacklist.obj_to_ip6(rule) unless (peer_ip.to_s.empty? || peer_ip.is_a?(IPAddr))
    raise default_exception.new(peer_ip, self, rule)
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
  
  def allowed_all?(*addrs)
    not denied_one?(*addrs)
  end
  
  alias_method :granted_all?, :allowed_all?

  # This method returns +true+ if access may be granted to IP
  # obtained from the given objects. Otherwise it returns +false+.
  # It has opposite behaviour to method denied?
  
  def allowed?(addr)
    not denied?(addr)
  end
  
  alias_method :granted?, :allowed?
  
  # This method returns +true+ if access may be granted to IPv6 address
  # from the given IPAddr object. Otherwise it returns +false+.
  # It has opposite behaviour to method ipaddr6_denied?
  
  def ipaddr6_granted?(addr)
    not ipaddr6_denied?(addr)
  end
  
  # This method is an alias for IPAddrList::Algorithm::IPv6BinarySearch#add on whitelist.

  def allow(*addrs)
    @whitelist.add(*addrs)
  end
  
  alias_method :permit, :allow
  alias_method :whitelist_add, :allow
  alias_method :add_to_whitelist, :allow
  
  # This method is an alias for IPAddrList::Algorithm::IPv6BinarySearch#del on whitelist.

  def disallow(*addrs)
    @whitelist.del(*addrs)
  end
  
  alias_method :unallow, :disallow
  alias_method :whitelist_del, :disallow
  alias_method :del_from_whitelist, :disallow
  
  # This method is an alias for IPAddrList::Algorithm::IPv6BinarySearch#add on blacklist.
  
  def deny(*addrs)
    @blacklist.add(*addrs)
  end
  
  alias_method :blacklist, :deny
  alias_method :blacklist_add, :deny
  alias_method :add_to_blacklist, :deny

  # This method is an alias for IPAddrList::Algorithm::IPv6BinarySearch#del on blacklist.
  
  def undeny(*addrs)
    @blacklist.del(*addrs)
  end

  alias_method :blacklist_del, :undeny
  alias_method :del_from_blacklist, :undeny
  
  # This method sets new black list removing all rules from
  # old black list first.
  
  def blacklist=(*args)
    @blacklist.clear
    @blacklist.add(*args)
  end

  # This method sets new white list removing all rules from
  # old black list first.
  
  def whitelist=(*args)
    @whitelist.clear
    @whitelist.add(*args)
  end
  
  # This method erases all rules.
  
  def clear
    @blacklist.clear
    @whitelist.clear
  end
  
  alias_method :erase, :clear
  
  # This method resets black list and white list
  # removing all rules first.
  
  def reset(blacklist=[], whitelist=[])
    self.blacklist = blacklist
    self.whitelist = whitelist
  end
  
  # This method returns +true+ if blacklist is empty.
  def empty?
    @blacklist.empty?
  end
  
  # This method checks IP access for IPAddr object.
  
  def check_addrinfo(peer)
    return peer if empty?
    peer_ip = IPAddr.new(peer)
    rule = ipaddr6_denied? ( peer_ip.ipv4? ? peer_ip.ipv4_compat : peer_ip )
    if rule
      # place for a block if any
      scream!(peer_ip, rule)
    end
    return peer
  end
  
  # This method checks IP access for IPAddr object.
  
  def check_ipaddr(peer_ip)
    return peer_ip if empty?
    rule = ipaddr6_denied? ( peer_ip.ipv4? ? peer_ip.ipv4_compat : peer_ip )
    if rule
      # place for a block if any
      scream!(peer_ip, rule)
    end
    return peer_ip
  end
  
  # This method checks IP access for socket object.
  
  def check_so(socket)
    return socket if empty?
    lookup_prev = socket.do_not_reverse_lookup
    peer_ip     = IPAddr(socket.peeraddr[3])
    socket.do_not_reverse_lookup = lookup_prev
    rule = ipaddr6_denied? ( peer_ip.ipv4? ? peer_ip.ipv4_compat : peer_ip )
    if rule
      # place for a block if any
      socket.close
      scream!(peer_ip, rule)
    end
    return socket
  end
  
  # This method checks IP access but bases on file descriptor.
  # Devel note: DRY is less important than time here!
  
  def check_fd(fd, list)
    return fd if empty?
    socket      = IPSocket.for_fd(fd)
    lookup_prev = socket.do_not_reverse_lookup
    peer_ip     = IPAddr.new(socket.peeraddr[3])
    socket.do_not_reverse_lookup = lookup_prev
    rule = ipaddr6_denied? ( peer_ip.ipv4? ? peer_ip.ipv4_compat : peer_ip )
    if rule
      # place for a block if any
      socket.close
      scream!(peer_ip, rule)
    end
    return fd
  end  
  
end


