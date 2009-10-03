# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# This file contains IPAccess class, which uses
# IPAccessList objects to implement IP input/output
# access control.
# 
#--
# 
# Copyright (C) 2009 by Paweł Wilk. All Rights Reserved.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version; or 2) Ruby's License.
# 
# See the file COPYING for complete licensing information.
#
#++

require 'socket'
require 'ipaccess/ip_access_list'
require 'ipaccess/ip_access_errors'

# This class maintains an access set.
# 
# Objects of IPAccess class, called <b>access sets</b>,
# contain two access lists which are available
# as accessible attributes: +input+ and +output+.
# 
# ==== Input and output
# 
# First list is for maintaining incoming IP
# traffic and second for outgoing traffic.
# Again, it is your free will to check IP addresses
# against input/output rules or not.
# 
# ==== Rules management
# 
# These two lists are instances of IPAccessList.
# Use IPAccessList instance methods to add or remove
# rules from this lists referenced by +input+ and
# +output+ attributes. Both IPv4 and IPv6 addresses
# are supported.
# 
# ==== Checking access
# 
# To check access you may call methods belonging
# to lists but it is recommended to use methods
# defined by this class. There are two groups
# of such methods, one for checking incoming traffic
# and the other one for checking outgoing traffic.
# 
# There are also different variants of this methods
# for different IP representations. That's because
# speed is important here. If you have a socket object
# you want to test then you should use method that
# checks sockets. If your IP is in text format you
# may want to use method that checks IP addresses
# written as strings.
# 
# ==== Exceptions
# 
# Access checking methods throw exceptions that are
# kind of IPAccessDenied. These exceptions contain
# IP addresses, rules that matched and diagnostic message.
# You can distinguish between errors related to incoming
# and outgoing traffic because checking methods throw
# different kind of exceptions dependently on
# what traffic caused them: IPAccessDenied::Input and
# IPAccessDenied::Output accordingly.
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
#     access.check_out(res)                 # check access for socket extracted from HTTP object
#     response = res.request(req)           # read response
#   end
#
# In the example above, which is probably more real
# than previous, we're using check_out method for testing
# Net::HTTP response object. The method is clever enough to
# extract IP socket from such object.
# 
# Although the problem still exists because
# access for incoming connection is validated
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
# sockets use IPAccess.arm class method. To
# use extended classes use classes like IPAccess::TCPSocket.

class IPAccess
  
  # Access list for incoming IP traffic. See IPAccessList class
  # for more information on how to manage it.
  
  attr_reader   :input
  
  alias_method  :in, :input
  alias_method  :incoming, :input
  
  # Access list for outgoing IP traffic. See IPAccessList class
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
    
  # Raises default exception including remote address and address-rule hash.
  # First argument should be a hash containing CIDR objects: a testet address
  # (+:IP+) and a matching rule (+:Rule+). Second argument should be exception class.
  
  def scream!(pair, use_exception=IPAccessDenied::Input)
    raise use_exception.new(pair[:IP], pair[:Rule], self)
  end
    
  # This method returns +true+ if all access lists are empty.
  # Otherwise returns +false+.
  
  def empty?
    @input.empty? && @output.empty?
  end
  
  # This method removes all rules from both input and
  # output access list.
  
  def clear!
    @input.clear!
    @output.clear!
  end
  
  # This method returns true if access set works
  # in bidirectional mode.
  
  def bidirectional?
    return (@output.object_id == @input.object_id)
  end
  
  # This method switches set to bidirectional
  # mode if the given argument is not +false+
  # and is not +nil+. When access set
  # operates in this mode there is no difference
  # between incoming and outgoing acceess list.
  # In bidirectional mode each access check
  # is performed against one list which contains
  # both input and output rules. Still the only
  # way to add or delete rules is to straight
  # call +input+ or +output+. The difference is
  # that these lists are linked together 
  # in bidirectional mode.
  # 
  # Be aware that switching mode will alter
  # your access lists. When switching to
  # bidirectional it will combine input and
  # output rules and put it into one list.
  # When switching back from bidirectional
  # to normal mode input and output lists
  # will have the same rules inside.
  # 
  # It may be good idea to prune access lists before
  # switching mode or to switch mode before adding
  # any rules to avoid unexpected results. You may
  # of course change mode anyway if you really know
  # what you are doing.
  
  def bidirectional=(enable)
    enable = enable ? true : false
    if enable != bidirectional?
      if enable
        @input.add @output
        @output.clear!
        @output = @input
      else
        @output = IPAccessList.new @input
      end
    end
    return nil
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
    pairs = list.denied(*args)
    unless pairs.empty?
      yield(pairs.first, args) if block_given?
      scream!(pairs.first, exc)
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
    rescue IOError, Errno::ENOTCONN, Errno::ENOTSOCK, ArgumentError # socket is not INET, not a socket nor connected
      return socket
    end
    peer_ip = NetAddr::CIDR.create(peeraddr.split('%').first)
    pair    = list.denied_cidr(peer_ip, true)
    unless pair.empty?
      yield(pair, socket) if block_given?
      scream!(pair, exc)
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
    peer_ip = NetAddr::CIDR.create(peeraddr.split('%').first)
    pair    = list.denied_cidr(peer_ip, true)
    unless pair.empty?
      yield(pair, sockaddr) if block_given?
      scream!(pair, exc)
    end
    return sockaddr
  end
  private :check_sockaddr

  # This method checks access for a CIDR object.
  
  def check_cidr(list, exc, cidr)
    pair = list.denied_cidr(cidr, true)
    unless pair.empty?
      yield(pair, cidr) if block_given?
      scream!(pair, exc)
    end
    return cidr
  end
  private :check_cidr
  
  # This method checks access for a string containing
  # IP address.
  
  def check_ipstring(list, exc, ipstring)
    return ipstring if list.empty?
    addr = NetAddr::CIDR.create(ipstring.split('%').first)
    pair = list.denied_cidr(addr, true)
    unless pair.empty?
      yield(pair, ipstring) if block_given?
      scream!(pair, exc)
    end
    return ipstring
  end
  private :check_ipstring
  
  # This method checks IP access but bases on file descriptor.
  
  def check_fd(list, exc, fd)
    check_socket(list, exc, Socket.for_fd(fd))
    return fd
  end
  private :check_fd
  
  # This method checks access for the given objects
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # a pair of values (first rejected IP and a matching rule).
  # If access is granted it returns an array containing
  # the given arguments.
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
  # a pair of values (first rejected IP and a matching rule).
  # If access is granted it returns an array containing
  # the given arguments.
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
  # a pair of values (rejected IP and a matching rule).
  # If access is granted it returns the given argument.
  # 
  # Expected argument should be kind of NetAddr::CIDR.

  def check_in_cidr(cidr)
    check_cidr(@input, IPAccessDenied::Input, cidr)
  end

  # This method checks access for the given CIDR object
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # a pair of values (rejected IP and a matching rule).
  # If access is granted it returns the given argument.
  # 
  # Expected argument should be kind of NetAddr::CIDR.
  
  def check_out_cidr(cidr)
    check_cidr(@output, IPAccessDenied::Output, cidr)
  end
  
  # This method checks access for the given string
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # a pair of values (rejected IP and a matching rule).
  # If access is granted it returns the given argument.
  
  def check_in_ipstring(ipstring)
    check_ipstring(@input, IPAccessDenied::Input, ipstring)
  end

  # This method checks access for the given string
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # a pair of values (rejected IP and a matching rule).
  # If access is granted it returns the given argument.
  
  def check_out_ipstring(ipstring)
    check_ipstring(@output, IPAccessDenied::Output, ipstring)
  end
  
  # This method checks access for the given socket object
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # a pair of values (rejected IP and a matching rule).
  # If access is granted it returns the given argument.
  # 
  # Expected argument should be kind of IPSocket.
  
  def check_in_socket(socket)
    check_socket(@input, IPAccessDenied::Input, socket)
  end

  # This method checks access for the given socket object
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # a pair of values (rejected IP and a matching rule).
  # If access is granted it returns the given argument.
  # 
  # Expected argument should be kind of IPSocket.
  
  def check_out_socket(socket)
    check_socket(@output, IPAccessDenied::Output, socket)
  end
  
  # This method checks access for the given sockaddr structure
  # containing IP information against input access list.
  # If access is denied it raises an exception reporting
  # a pair of values (rejected IP and a matching rule).
  # If access is granted it returns the given argument.
  
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
  # a pair of values (rejected IP and a matching rule).
  # If access is granted it returns the given argument.
  # 
  # Expected argument should be a number representing a valid
  # file descriptor bound to an IP socket.
      
  def check_in_fd(fd)
    check_fd(@input, IPAccessDenied::Input, fd)
  end

  # This method checks access for the given file descriptor
  # containing IP information against output access list.
  # If access is denied it raises an exception reporting
  # a pair of values (rejected IP and a matching rule).
  # If access is granted it returns the given argument.
  # 
  # Expected argument should be a number representing a valid
  # file descriptor bound to an IP socket.
  
  def check_out_fd(fd)
    check_fd(@output, IPAccessDenied::Output, fd)
  end
  
  # This method shows access set in human readable form.
  
  def show
    ".=========================================.\n"   +
    ". ACL for incomming traffic:\n\n"                +
    @input.show                                       +
    "\n.=========================================.\n" +
    ". ACL for outgoing traffic:\n\n"                 +
    @output.show + "\n\n"
  end
  
end




  
