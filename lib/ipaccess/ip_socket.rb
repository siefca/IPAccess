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

require 'ipaddr'
require 'socket'
require 'ipaddr_list'
require 'ipaccess/ip_access'
require 'ipaccess/ip_access_errors'

IPAccess::In        = IPAccess.new
IPAccess::Out       = IPAccess.new
IPAccess::In.name   = 'global'
IPAccess::Out.name  = 'global'

# This version of IPSocket class uses IPAccess
# to control incomming and outgoing connections.

#module IPSocketAccess

class TCPServer
  
  alias orig_initialize       initialize
  alias orig_accept           accept
  alias orig_accept_nonblock  accept_nonblock
  alias orig_sysaccept        sysaccept
  
  # This method returns currently used IP access list.
  
  def access
    @access || IPAccess::In
  end
  alias_method :acl, :access
  
  # This method enables usage of internal IP access list for object.
  # If argument is IPAccess object then it is used. If argument is other
  # kind it is assumed that it should be converted to IPAccess object
  # and give initial information about black list.
  # 
  # If argument is +nil+ then IP access list is disabled for specific socket. That means
  # only global IP access checks will be done, of course only if list IPAccess::In
  # (for incomming packets) and/or list IPAccess::Out (for outgoing packets)
  # are not empty.
  #
  # Examples:
  #
  #     socket = TCPSocket('randomseed.pl', 80)       # new socket
  #     socket.access = IPAccess.new                  # new, empty access list
  #     socket.access = '192.168.0.0/16', '1.2.3.4'   # new access list with blacklist
  #     socket.access = []                            # other way to create empty list              
  #     socket.access = nil                           # disables IP access list for socket
  #                                                   # (global IP access lists may be still in use!)
  
  def access=(obj)
    if (obj.nil? || obj.is_a?(IPAccess))
      @access = obj
    else
      @access = IPAccess.new(obj, [])
    end
  end
  
  # This method check IP access.
  
  def acl_check(socket)
    alist = @access || IPAccess::In
    return socket if alist.empty?
    lookup_prev = socket.do_not_reverse_lookup
    peer_ip     = IPAddr(socket.peeraddr[3])
    peer_ip     = peer_ip.ipv4_compat if peer_ipv4?
    socket.do_not_reverse_lookup = lookup_prev
    if rule=alist.ipaddr6_denied?(peer_ip)
      # place for a block if any
      socket.close
      raise IPAccessDenied::Input.new(peer_ip, alist, rule)
    end
    return socket
  end
  private :acl_check
  
  # This method check IP access but bases on file descriptor.
  
  def acl_check_fd(fd)
    alist = @access || IPAccess::In
    return fd if alist.empty?
    socket      = IPSocket.for_fd(fd)
    lookup_prev = socket.do_not_reverse_lookup
    peer_ip     = IPAddr.new(socket.peeraddr[3])
    peer_ip     = peer_ip.ipv4_compat if peer_ip.ipv4?
    socket.do_not_reverse_lookup = lookup_prev
    if rule=alist.ipaddr6_denied?(peer_ip)
      # place for a block if any
      socket.close
      raise IPAccessDenied::Input.new(peer_ip, alist, rule)
    end
    return fd
  end
  private :acl_check_fd
  
  
  def initialize(*args)
    @access = nil
    return orig_initialize(*args)
  end
  
  # Accept on steroids.

  def accept(*args)
    acl_check orig_accept(*args)
  end
  
  # Sysaccept on steroids.
  
  def sysaccept(*args)
    acl_check_fd orig_sysaccept(*args)
  end
  
  # Accept_nonblock on steroids.
  
  def accept_nonblock(*args)
    acl_check orig_accept_nonblock(*args)
  end
  
end

# TCPServer.send(:include, IPSocketAccess)

serv = TCPServer.new(2202)
#serv.access = "127.0.0.1"
IPAccess::In.deny "127.0.0.1/8"
serv.access
     begin
       sock = serv.sysaccept #_nonblock
     rescue Errno::EAGAIN, Errno::ECONNABORTED, Errno::EPROTO, Errno::EINTR
       #IO.select([serv])
       retry
     end





