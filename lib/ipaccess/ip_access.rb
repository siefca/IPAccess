# encoding: utf-8
# 
# === ip_access
# 
# This file contains IPAccess class, which uses
# IPAccessList to implement IP input/output
# access list.
#
# Easy to manage and fast IP access lists.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   LGPL

$LOAD_PATH.unshift '..'

require 'ipaddr_list'
require 'ipaccess/ip_access_list'
require 'ipaccess/ip_access_errors'

# This class creates access lists for input and output, in order
# manage IP access. Each list is IPAccessList object containing
# white and black list.

class IPAccess
  
  # Incoming traffic.
  
  attr_reader   :input
  alias_method  :in, :input
  
  # Outgoing traffic.
  
  attr_reader   :output
  alias_method  :out, :output
  
  # Descriptive name of this object. Used in error reporting.
  
  attr_accessor :name
  
  # This method creates new IPAccess object. It optionally takes
  # two IPAccessList objects (initial data for black list and white list).
    
  def initialize(input=nil, output=nil)
    @name = nil
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
  
  # This method resets input list and output list
  # removing all rules first.
  
  def reset(input=[], whitelist=[])
    self.input = input
    self.output = output
  end
  
  # This method returns +true+ if all access lists are empty.
  
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
  
  # This method checks IP access for socket object.
  
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
  
  # This method checks IP access for CIDR object.
  
  def check_cidr(list, exc, peer_ip)
    rule = list.denied_cidr(peer_ip, true)
    unless rule.nil?
      # place for a block if any
      scream!(rule, exc)
    end
    return peer_ip
  end
  private :check_cidr
  
  # This method checks IP access for CIDR object.
  
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
  # Devel note: DRY is less important than time here!
  
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
  
  # This method checks access of incoming traffic for
  # the given CIDR objects. If access is denied it
  # raises an exception reporting first rejected IP.
  # If access is granted it returns the given argument(s).
  # 
  # See IPAccessList.obj_to_cidr description for more info
  # about arguments you may pass to it.
  
  def check_in(*args)
    check(@input, IPAccessDenied::Input, *args)
  end
  
  # This method checks access of outgoing traffic for
  # the given CIDR objects. If access is denied it
  # raises an exception reporting first rejected IP.
  # If access is granted it returns the given argument(s).
  # 
  # See IPAccessList.obj_to_cidr description for more info
  # about arguments you may pass to it.
  
  def check_out(*args)
    check(@output, IPAccessDenied::Output, *args)
  end

  def check_in_cidr(peer_ip)
    check_cidr(@input, IPAccessDenied::Input, peer_ip)
  end
  
  def check_out_cidr(peer_ip)
    check_cidr(@output, IPAccessDenied::Output, peer_ip)
  end
  
  def check_in_ipstring(peer_ip)
    check_ipstring(@input, IPAccessDenied::Input, peer_ip)
  end
  
  def check_out_ipstring(peer_ip)
    check_ipstring(@output, IPAccessDenied::Output, peer_ip)
  end
  
  def check_in_so(socket)
    check_so(@input, IPAccessDenied::Input, socket)
  end
  
  def check_out_so(socket)
    check_so(@output, IPAccessDenied::Output, socket)
  end
    
  def check_in_fd(fd)
    check_fd(@input, IPAccessDenied::Input, fd)
  end
  
  def check_out_fd(fd)
    check_fd(@output, IPAccessDenied::Output, fd)
  end
    
end

