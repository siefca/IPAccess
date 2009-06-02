# encoding: utf-8
# 
# Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This is licensed under LGPL or Ruby License.
# 
# === ip_access
# 
# This file contains IPAccess class, which uses
# IPAccessList objects to implement IP input/output
# access list.

$LOAD_PATH.unshift '..'

require 'socket'
require 'ipaddr_list'
require 'ipaccess/ip_access_list'
require 'ipaccess/ip_access_errors'

# This class maintains access set that
# contains two access lists: +input+ for
# incomming traffic and +output+ for
# outgoing traffic. Each access list
# is an IPAccessList object containing 
# white and black rules controling IP access.
# It has methods that are able to check access
# for given objects containing IP addresses.
# Both IPv4 and IPv6 addresses are supported.
# 
# This class has no methods
# that actualy do network operations, it just
# allows you to check IP access for already
# given objects.
# 
# Access lists objects containing
# rules are present in members called +input+ and +output+.
# Use IPAccessList instance methods to add or remove
# rules from this lists.
# 
# When access for tested IP is denied validating
# methods of this class throw IPAccessDenied exceptions:
# IPAccessDenied::Input for input rules and
# IPAccessDenied::Output in case of output rules.
# 
# ==== Usage examples
# 
#   access = IPAccess.new 'mylist'    # create access set
#   access.input.block :private       # input list: block private subnets
#   access.input.permit '192.168.1.1' # input list: but permit 192.168.1.1 
#   access.check_in '192.168.1.1'     # should pass
#   access.check_in '192.168.1.2'     # should raise an exception
# 
# In the example above checking access is covered
# by the check_in method. It is generic, easy to use
# routine, but if you are fan of performance
# you may want to use dedicated methods designed
# to handle single IP stored in socket, file descriptor,
# NetAddr::CIDR object, sockaddr structure or IP string.
#
#   require 'uri'
#   require 'net/http'
# 
#   access = IPAccess.new 'outgoing http'   # create access set
#   access.output.block :all                # output list: block all
#   
#   url = URI('http://randomseed.pl/')      # parse URL
#   res = Net::HTTP.new(url.host, url.port) # create HTTP resource
#   req = Net::HTTP::Get.new(url.path)      # create HTTP request
# 
#   res.start do                            # start HTTP session
#     access.check_out(res)                 # check access for socket extracted from http object
#     response = res.request(req)           # read response
#   end
#
# In the example above, which is probably more real
# than previous, we're using check_out method for testing
# Net::HTTP response object. The method is clever enough to
# extract IP socket from such object.
# 
# Although the problem still exists because
# access for incomming connection is validated
# after the HTTP session has already started. We cannot
# be 100% sure whether any data has been sent or not.
# The cause of that problem is lack of controlled
# low-level connect operation that we can issue in
# that particular case.
# 
# To fix issues like that you may want to
# globally enable IP access control for original
# Ruby's socket classes or use special versions
# of them shipped with this library. To patch original
# sockets use arm class method of IPAccess and to
# use extended classes use classes like IPAccess::TCPSocket.

class IPAccess
  
  # Incoming traffic list. See IPAccessList class
  # for more information on how to manage it.
  
  attr_reader   :input
  
  alias_method  :in, :input
  alias_method  :incoming, :input
  
  # Outgoing traffic list. See IPAccessList class
  # for more information on how to manage it.
  
  attr_reader   :output
  
  alias_method  :out, :output
  alias_method  :outgoing, :output
  
  # Descriptive name of this object. Used in error reporting.
  
  attr_accessor :name
  
  # This method creates new IPAccess object. It optionally takes
  # two IPAccessList objects (initial data for access lists)
  # and a name of an access set used in error reporting.
  # 
  # If there is only one argument it is assumed that it also
  # contains this set's descriptive name.
  
  def initialize(input=nil, output=nil, name=nil)
    @name = nil
    @name, input = input, nil if (output.nil? && name.nil?)
    @input  = IPAccessList.new(input)
    @output = IPAccessList.new(output)
    return self
  end
  
  # Raises default exception including remote address and rule object.
  # First argument should be an array containing CIDR objects: a testet address
  # and a matching rule. Second argument should be exception class.
  
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
    return args if list.empty?
    rules = list.denied(*args)
    unless rules.empty?
      yield(rules.first, args) if block_given?
      scream!(rules.first, exc)
    end
    return args
  end
  private :check
  
  # This method checks access for a socket.
  
  def check_socket(list, exc, socket)
    if (list.empty? || !socket.respond_to?(:getpeername))
      return socket
    end
    begin
      peeraddr = Socket.unpack_sockaddr_in(socket.getpeername).last
    rescue Errno::ENOTCONN, Errno::ENOTSOCK, ArgumentError # socket is not INET, not a socket or not connected
      return socket
    end
    peer_ip = NetAddr::CIDR.create(peeraddr)
    rule    = list.denied_cidr(peer_ip, true)
    unless rule.nil?
      yield(rule, socket) if block_given?
      scream!(rule, exc)
    end
    return socket
  end
  private :check_socket
  
  # This method checks access for a sockaddr.
  
  def check_sockaddr(list, exc, sockaddr)
    return sockaddr if list.empty?
    begin
      peeraddr = Socket.unpack_sockaddr_in(sockaddr).last
    rescue ArgumentError # sockaddr is not INET
      return sockaddr
    end
    peer_ip = NetAddr::CIDR.create(peeraddr)
    rule    = list.denied_cidr(peer_ip, true)
    unless rule.nil?
      yield(rule, sockaddr) if block_given?
      scream!(rule, exc)
    end
    return sockaddr
  end
  private :check_sockaddr

  # This method checks access for a CIDR object.
  
  def check_cidr(list, exc, cidr)
    rule = list.denied_cidr(cidr, true)
    unless rule.nil?
      yield(rule, cidr) if block_given?
      scream!(rule, exc)
    end
    return cidr
  end
  private :check_cidr
  
  # This method checks access for a string containing
  # IP address.
  
  def check_ipstring(list, exc, ipstring)
    return ipstring if list.empty?
    addr = NetAddr::CIDR.create(ipstring)
    rule = list.denied_cidr(addr, true)
    unless rule.nil?
      yield(rule, ipstring) if block_given?
      scream!(rule, exc)
    end
    return ipstring
  end
  private :check_ipstring
  
  # This method checks IP access but bases on file descriptor.
  
  def check_fd(list, exc, fd)
    check_socket(list, exc, Socket.for_fd(fd))
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

  def check_in_cidr(cidr)
    check_cidr(@input, IPAccessDenied::Input, cidr)
  end

  # This method checks access for the given CIDR object
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  # 
  # Expected argument should be kind of NetAddr::CIDR.
  
  def check_out_cidr(cidr)
    check_cidr(@output, IPAccessDenied::Output, cidr)
  end
  
  # This method checks access for the given string
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  
  def check_in_ipstring(ipstring)
    check_ipstring(@input, IPAccessDenied::Input, ipstring)
  end

  # This method checks access for the given string
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  
  def check_out_ipstring(ipstring)
    check_ipstring(@output, IPAccessDenied::Output, ipstring)
  end
  
  # This method checks access for the given socket object
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  # 
  # Expected argument should be kind of IPSocket.
  
  def check_in_socket(socket)
    check_socket(@input, IPAccessDenied::Input, socket)
  end

  # This method checks access for the given socket object
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  # 
  # Expected argument should be kind of IPSocket.
  
  def check_out_socket(socket)
    check_socket(@output, IPAccessDenied::Output, socket)
  end
  
  # This method checks access for the given sockaddr structure
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  
  def check_in_sockaddr(sockaddr)
    check_sockaddr(@input, IPAccessDenied::Input, sockaddr)
  end

  # This method checks access for the given sockaddr structure
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # rejected IP and a matching rule. If access is granted
  # it returns the given argument.
  
  def check_out_sockaddr(sockaddr)
    check_sockaddr(@output, IPAccessDenied::Output, sockaddr)
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


