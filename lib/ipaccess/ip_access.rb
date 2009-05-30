# encoding: utf-8
# 
# Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   LGPL
# 
# === ip_access
# 
# This file contains IPAccess class, which uses
# IPAccessList objects to implement IP input/output
# access list.

$LOAD_PATH.unshift '..'

require 'ipaddr_list'
require 'ipaccess/ip_access_list'
require 'ipaccess/ip_access_errors'

# This class creates two lists maintaining
# access control for incoming and outgoing
# IP traffic. Both IPv4 and IPv6 addresses
# are supported.
#
# Usage example:
#
#   access = IPAccess.new 'mylist'    # create access lists
#   access.input.block :private       # input: block private subnets
#   access.input.permit '192.168.1.1' # input: but permit 192.168.1.1 
#   access.check_in '192.168.1.1'     # should pass
#   access.check_in '192.168.1.2'     # should raise an exception
# 
# In the above example checking access is covered
# by the check_in method. It's generic, easy to use
# routine, but if you are fan of performance
# you may want to use dedicated methods designed
# to handle single IP stored in socket, file descriptor,
# NetAddr::CIDR object or string.

class IPAccess
  
  # Incoming traffic lists. See IPAccessList class
  # for more information on how to manage it.
  
  attr_reader   :input
  
  alias_method  :in, :input
  alias_method  :incoming, :input
  
  # Outgoing traffic lists. See IPAccessList class
  # for more information on how to manage it.
  
  attr_reader   :output
  
  alias_method  :out, :output
  alias_method  :outgoing, :output
  
  # Descriptive name of this object. Used in error reporting.
  
  attr_accessor :name
  
  # This method creates new IPAccess object. It optionally takes
  # two IPAccessList objects (initial data for black list and white list)
  # and a name for list (used in error reporting).
  # 
  # If there is only one argument it is assumed that it also
  # contains this list's descriptive name.
  
  def initialize(input=nil, output=nil, name=nil)
    @name = nil
    @name, input = input, nil if (output.nil? && name.nil?)
    @input  = IPAccessList.new(input)
    @output = IPAccessList.new(output)
    return self
  end
  
  def input=(*args)
    IPAccessList.new(*args)
  end

  def output=(*args)
    IPAccessList.new(*args)
  end
  
  # Raises default exception including remote address and rule object.
  # First argument should be an array containing CIDR objects: testet address
  # and matching rule. Second argument should be exception class.
  
  def scream!(rule, use_exception=IPAccessDenied::Input)
    peer_ip = rule.shift
    rule = rule.first
    raise use_exception.new(peer_ip, rule, self)
  end
    
  # This method returns +true+ if all access lists are empty.
  # Otherwise returns +false+.
  
  def empty?
    @input.empty? && @output.empty?
  end

  # This method checks IP access of traffic for
  # CIDR objects. If access is denied it raises an exception
  # reporting first rejected IP. If access is granted it
  # returns an array containing the given argument(s).
  # 
  # See IPAccessList.obj_to_cidr description for more info
  # about arguments you may pass to it.
  
  def check(list, exc, *args)
    rules = list.denied(*args)
    unless rules.empty?
      # place for a block if any
      scream!(rules.first, exc)
    end
    return args
  end
  private :check
  
  # This method checks access for a socket.
  
  def check_so(list, exc, socket)
    return socket if empty?
    lookup_prev = socket.do_not_reverse_lookup
    peer_ip     = NetAddr::CIDR.create(socket.peeraddr[3])
    socket.do_not_reverse_lookup = lookup_prev
    rule        = list.denied_cidr(peer_ip, true)
    if rule
      # place for a block if any
      socket.close
      scream!(rule)
    end
    return socket
  end
  private :check_so
  
  # This method checks access for a CIDR object.
  
  def check_cidr(list, exc, peer_ip)
    rule = list.denied_cidr(peer_ip, true)
    unless rule.nil?
      # place for a block if any
      scream!(rule, exc)
    end
    return peer_ip
  end
  private :check_cidr
  
  # This method checks access for a string containing
  # IP address.
  
  def check_ipstring(list, exc, peer_ip)
    addr = NetAddr::CIDR.create(peer_ip)
    rule = list.denied_cidr(addr, true)
    unless rule.nil?
      # place for a block if any
      scream!(rule, exc)
    end
    return peer_ip
  end
  private :check_ipstring
  
  # This method checks IP access but bases on file descriptor.
  
  def check_fd(fd, list, exc)
    return fd if empty?
    socket      = IPSocket.for_fd(fd)
    lookup_prev = socket.do_not_reverse_lookup
    peer_ip     = NetAddr::CIDR.create(socket.peeraddr[3])
    socket.do_not_reverse_lookup = lookup_prev
    rule        = list.denied_cidr(peer_ip, true)
    if rule
      # place for a block if any
      socket.close
      scream!(rule, exc)
    end
    return fd
  end
  private :check_fd
  
  # This method checks access for the given objects
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # first rejected IP and a matching rule. If access is
  # granted it returns an array containing the given arguments.
  # 
  # See IPAccessList.obj_to_cidr description for more info
  # about arguments you may pass to it.
  # 
  # You may also want to use more efficient access checking
  # methods if your object contains information about
  # single IP and has a known type.
  
  def check_in(*args)
    check(@input, IPAccessDenied::Input, *args)
  end
  
  # This method checks access for the given objects
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # first rejected IP and a matching rule. If access is
  # granted it returns an array containing the given arguments.
  # 
  # See IPAccessList.obj_to_cidr description for more info
  # about arguments you may pass to it.
  # 
  # You may also want to use more efficient access checking
  # methods if your object contains information about
  # single IP and has a known type.
  
  def check_out(*args)
    check(@output, IPAccessDenied::Output, *args)
  end
  
  # This method checks access for the given CIDR object
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  # 
  # Expected argument should be kind of NetAddr::CIDR.

  def check_in_cidr(peer_ip)
    check_cidr(@input, IPAccessDenied::Input, peer_ip)
  end

  # This method checks access for the given CIDR object
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  # 
  # Expected argument should be kind of NetAddr::CIDR.
  
  def check_out_cidr(peer_ip)
    check_cidr(@output, IPAccessDenied::Output, peer_ip)
  end
  
  # This method checks access for the given string
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  
  def check_in_ipstring(peer_ip)
    check_ipstring(@input, IPAccessDenied::Input, peer_ip)
  end

  # This method checks access for the given string
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  
  def check_out_ipstring(peer_ip)
    check_ipstring(@output, IPAccessDenied::Output, peer_ip)
  end
  
  # This method checks access for the given socket object
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  # 
  # Expected argument should be kind of IPSocket.
  
  def check_in_so(socket)
    check_so(@input, IPAccessDenied::Input, socket)
  end

  # This method checks access for the given socket object
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  # 
  # Expected argument should be kind of IPSocket.
  
  def check_out_so(socket)
    check_so(@output, IPAccessDenied::Output, socket)
  end
  
  # This method checks access for the given file descriptor
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  # 
  # Expected argument should be a number representing a valid
  # file descriptor bound to an IP socket.
      
  def check_in_fd(fd)
    check_fd(@input, IPAccessDenied::Input, fd)
  end

  # This method checks access for the given file descriptor
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  # 
  # Expected argument should be a number representing a valid
  # file descriptor bound to an IP socket.
  
  def check_out_fd(fd)
    check_fd(@output, IPAccessDenied::Output, fd)
  end
  
end


