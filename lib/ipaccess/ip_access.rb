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

# This class includes two lists for maintaining
# access control of incoming and outgoing
# IP traffic. It allows you to build IP access
# lists (white and black) for input and output
# and then check objects containing IP addresses
# against that lists. Both IPv4 and IPv6 addresses
# are supported.
#
# This class internally uses IPAccessList objects
# present in members called input and output.
# Use IPAccessList to add or remove rules from
# this lists.
# 
# When access is denied this class methods
# use IPAccessDenied exceptions: IPAccessDenied::Input
# and IPAccessDenied::Output.
# 
# ==== Usage examples
# 
#   access = IPAccess.new 'mylist'    # create access lists
#   access.input.block :private       # input: block private subnets
#   access.input.permit '192.168.1.1' # input: but permit 192.168.1.1 
#   access.check_in '192.168.1.1'     # should pass
#   access.check_in '192.168.1.2'     # should raise an exception
# 
# In the example above checking access is covered
# by the check_in method. It is generic, easy to use
# routine, but if you are fan of performance
# you may want to use dedicated methods designed
# to handle single IP stored in socket, file descriptor,
# NetAddr::CIDR object or string.
#
#   require 'uri'
#   require 'net/http'
# 
#   access = IPAccess.new 'outgoing http'   # create access lists
#   access.output.block :all                # output: block all
#   
#   url = URI('http://randomseed.pl/')      # parse URL
#   res = Net::HTTP.new(url.host, url.port) # create HTTP resource
#   req = Net::HTTP::Get.new(url.path)      # create HTTP request
# 
#   res.start do                            # start HTTP session
#     access.check_out(res)                 # check access for socket from http object
#     response = res.request(req)           # read response
#   end
#
# In the example above, which BTW is probably more real
# than previous, we're using check_out method for testing
# Net::HTTP response object. The method is clever and
# can extract IP socket from such object.
# 
# Although the problem still exists because we're
# able to check output access after the session has
# already started. That means the program logic will
# get the access information after HTTP connection
# had been established and it would be able to drop
# it eventually but not avoid it entirely.
# 
# The cause of that problem are sockets in Ruby, which
# are sometimes so abstract that there is no way to
# create TCP socket without making a connection. To fix
# that you may use IPSocketAccess module provided
# with this library. It will allow you to equip all
# or selected sockets with access control.

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
    return args if empty?
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
    return peer_ip if empty?
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
  
  def check_fd(list, exc, fd)
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


