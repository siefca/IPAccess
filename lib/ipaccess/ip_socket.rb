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

$LOAD_PATH.unshift '..'

require 'ipaddr'
require 'socket'
require 'ipaddr_list'
require 'ipaccess/ip_access'
require 'ipaccess/ip_access_errors'

IPAccess::In        = IPAccess.new IPAccessDenied::Input
IPAccess::Out       = IPAccess.new IPAccessDenied::Output
IPAccess::In.name   = 'global'
IPAccess::Out.name  = 'global'

# This module patches classes to use IP-access control
# by using IPAccess object.

module IPSocketAccess

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
  
  def acl=(obj)
    if (obj.nil? || obj.is_a?(IPAccess))
      @acl = obj
    else
      @acl = IPAccess.new(obj, [])
    end
  end
  
end

# TCPServer class with IP access control.

class TCPServer
  
  alias orig_initialize       initialize
  alias orig_accept           accept
  alias orig_accept_nonblock  accept_nonblock
  alias orig_sysaccept        sysaccept
  
  include IPSocketAccess

  def initialize(*args)
    @acl = nil
    return orig_initialize(*args)
  end
  
  # accept on steroids.
  def accept(*args)
    acl = @acl || IPAccess::In
    acl.check_so orig_accept(*args)
  end
  
  # accept_nonblock on steroids.
  def accept_nonblock(*args)
    acl = @acl || IPAccess::In
    acl.check_so orig_accept_nonblock(*args)
  end
  
  # sysaccept on steroids.    
  def sysaccept(*args)
    acl = @acl || IPAccess::In
    acl.check_fd orig_sysaccept(*args)
  end

end

# TCPSocket class with IP access control.

class TCPSocket
  
  alias orig_initialize         initialize
  
  include IPSocketAccess
  
  def initialize(hostName, port, accessList=nil)
    @acl  = accessList
    acl   = @acl || IPAccess::Out
    addr  = self.class.getaddress(hostName)
    acl.check_addrinfo addr
    orig_initialize(addr, port)
    return self
  end

end

IPAccess::Out.deny   'wykop.pl'

s = TCPSocket.new('wykop.pl', 80)

#serv = TCPServer.new(2202)
##serv.access = "127.0.0.1"
#IPAccess::In.deny   :all
#
##IPAccess::In.allow  "127.0.0.1", :localhost
#p serv.access
#     begin
#       sock = serv.sysaccept #_nonblock
#     rescue Errno::EAGAIN, Errno::ECONNABORTED, Errno::EPROTO, Errno::EINTR
#       #IO.select([serv])
#       retry
#     end
