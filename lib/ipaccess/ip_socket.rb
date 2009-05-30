# encoding: utf-8
#
# Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   LGPL
# 
# === ip_socket
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

IPAccess::Global = IPAccess.new 'global'

# This module patches socket handling classes
# to use IP access control. Each patched socket
# class has acl member, which is an IPAccess object.
# 
# 
# Examples:
#
#     serv = TCPServer.new(31337)                   # create listening TCP socket
#     serv.acl = :local                             # create and use local access lists
#     serv.acl.input.block '1.2.3.4/16'             # block 1.2.0.0/16
#     serv.acl.input.block :local, :private         # block local and private addresses
#     serv.acl.input.permit '127.0.0.5'             # make an exception
#     puts list.input.blacklist                     # show blacklisted IP addresses
#     puts list.input.whitelist                     # show whitelisted IP addresses
#     sock = serv.sysaccept                         # accept connection
#
#     list = IPAccess.new 'my list'                 # will use external access lists
#     list.output.block '1.2.3.4/16'                # block connections to 1.2.0.0/16
#     list.output.block 'randomseed.pl'             # block connections to IP address of randomseed.pl
#     socket = TCPSocket('randomseed.pl', 80, list) # create connected TCP socket with list assigned

module IPSocketAccess

  # This method enables usage of internal IP access list for object.
  # If argument is IPAccess object then it is used. If argument is other
  # kind it is assumed that it should be converted to IPAccess object
  # and give initial information about black list.
  # 
  # Examples:
  #
  #     socket.acl = :global        # use global access lists
  #     socket.acl = :local         # create and use local access lists
  #     socket.acl = IPAccess.new   # use external (shared) access lists

  def acl=(obj)
    if obj.is_a?(Symbol)
      case obj
      when :global
        @acl = nil
      when :local
        @acl = IPAccess.new
      else
        raise ArgumentError, "bad access list selector, use: :global or :local"
      end
    elsif obj.is_a?(IPAccess)
      @acl = obj 
    else
      raise ArgumentError, "bad access list"
    end
  end
  
  attr_reader :acl
  alias_method :access=, :acl=
  alias_method :access, :acl
  
end

# TCPServer class with IP access control.
# It uses input access lists.

class TCPServer
  
  # :stopdoc:
  alias orig_initialize       initialize
  alias orig_accept           accept
  alias orig_accept_nonblock  accept_nonblock
  alias orig_sysaccept        sysaccept
  # :startdoc:
  
  include IPSocketAccess

  def initialize(*args)
    @acl = nil
    return orig_initialize(*args)
  end
  
  # accept on steroids.
  def accept(*args)
    acl = @acl || IPAccess::Global
    acl.check_in_so orig_accept(*args)
  end
  
  # accept_nonblock on steroids.
  def accept_nonblock(*args)
    acl = @acl || IPAccess::Global
    acl.check_in_so orig_accept_nonblock(*args)
  end
  
  # sysaccept on steroids.
  def sysaccept(*args)
    acl = @acl || IPAccess::Global
    acl.check_in_fd orig_sysaccept(*args)
  end

end

# TCPSocket class with IP access control.
# It uses output access lists.

class TCPSocket
  
  # :stopdoc:
  alias orig_initialize         initialize
  # :startdoc:
  
  include IPSocketAccess
  
  def initialize(hostName, port, accessList=:global)
    self.acl = accessList
    acl = @acl || IPAccess::Global
    addr = self.class.getaddress(hostName)
    acl.check_out_ipstring(addr)
    orig_initialize(addr, port)
    return self
  end
  
end

serv = TCPServer.new(2202)
serv.access = :local
serv.access.in.block :local
#IPAccess::In.deny   :all
#
##IPAccess::In.allow  "127.0.0.1", :localhost
#p serv.access
     begin
       sock = serv.sysaccept #_nonblock
     rescue Errno::EAGAIN, Errno::ECONNABORTED, Errno::EPROTO, Errno::EINTR
       #IO.select([serv])
       retry
     end
