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
# ==== Examples
#
# ===== +TCPServer+
#     serv = TCPServer.new(31337)                   # create listening TCP socket
#     serv.acl = :local                             # create and use local access lists
#     serv.acl.input.block :local, :private         # block local and private addresses
#     serv.acl.input.permit '127.0.0.5'             # make an exception
#     puts serv.acl.input.blacklist                 # show blacklisted IP addresses
#     puts serv.acl.input.whitelist                 # show whitelisted IP addresses
#     sock = serv.sysaccept                         # accept connection
#
# ===== +TCPSocket+
#     list = IPAccess.new 'my list'                     # we will use external access lists
#     list.output.block '1.2.3.4/16'                    # block connections to 1.2.0.0/16
#     list.output.block 'randomseed.pl'                 # block connections to IP address of randomseed.pl
#     socket = TCPSocket.new('randomseed.pl', 80, list) # create connected TCP socket with access control
# 
# Note that in this example we cannot alter
# access list after creating socket since
# TCPSocket instance does connect at the very
# beginning of existence.
#
# ===== +Socket+
#     require 'socket'
#     include Socket::Constants
#     
#     IPAccess::Global.input.blacklist :localhost         # add localhost to global input black list
#     socket = Socket.new(AF_INET, SOCK_STREAM, 0)        # create TCP socket
#     sockaddr = Socket.sockaddr_in(31337, '127.0.0.1')   # create sockadr_in structure
#     socket.bind(sockaddr)                               # bind to port 31331 and IP 127.0.0.1
#     socket.listen(5)                                    # listen on socket
#     begin
#       c_socket, c_sockaddr = socket.accept_nonblock     # call non-blocking accept for connections
#     rescue Errno::EAGAIN, Errno::ECONNABORTED,
#            Errno::EPROTO, Errno::EINTR                  
#       IO.select([socket])                               # retry on retriable errors
#       retry
#     rescue IPAccessDenied                               # when access is denied
#       c_socket.close                                    # close client socket
#       socket.close                                      # close listener
#       raise                                             # raise exception
#     end
#     c_socket.puts "Hello world!"                        # otherwise continue
#     c_socket.close
#     socket.close


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
    acl.check_in_socket orig_accept(*args)
  end
  
  # accept_nonblock on steroids.
  def accept_nonblock(*args)
    acl = @acl || IPAccess::Global
    acl.check_in_socket orig_accept_nonblock(*args)
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
  alias orig_initialize        initialize
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

# UDPSocket class with IP access control.
# It uses output access lists.

class UDPSocket
  
  # :stopdoc:
  alias orig_connect            connect
  alias orig_send               send
  alias orig_recvfrom           recvfrom
  alias orig_recvfrom_nonblock  recvfrom_nonblock
  # :startdoc:
  
  include IPSocketAccess
  
  # connect on steroids.
  def connect(*args)
    acl = @acl || IPAccess::Global
    peer_ip = self.class.getaddress(args.shift)
    acl.check_out_sockaddr(peer_ip)
    return orig_connect(peer_ip, *args)
  end
  
  # send on steroids.
  def send(*args)
    hostname = args[2]
    return orig_send(*args) if hostname.nil?
    acl = @acl || IPAccess::Global
    peer_ip = self.class.getaddress(hostname)
    acl.check_out_sockaddr(peer_ip)
    args[2] = peer_ip
    return orig_send(*args)
  end
  
  # recvfrom on steroids.
  def recvfrom(*args)
    acl = @acl || IPAccess::Global
    ret = orig_recvfrom(*args)
    peer_ip = ret[1][3]
    family = ret[1][0]
    if (family == "AF_INET" || family == "AF_INET6")
      acl.check_in_ipstring(peer_ip)
    end
    return ret
  end
  
  # recvfrom_nonblock on steroids.
  def recvfrom_nonblock(*args)
    acl = @acl || IPAccess::Global
    ret = orig_recvfrom(*args)
    peer_ip = ret[1][3]
    family = ret[1][0]
    if (family == "AF_INET" || family == "AF_INET6")
      acl.check_in_ipstring(peer_ip)
    end
    return ret
  end
  
  
end

# SOCKSSocket class with IP access control.
# It uses output access lists.

class SOCKSSocket
  
  # :stopdoc:
  alias orig_initialize        initialize
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

# Socket class with IP access control.
# It uses input and output access lists.

class Socket

  # :stopdoc:
  alias orig_initialize       initialize
  alias orig_accept           accept
  alias orig_accept_nonblock  accept_nonblock
  alias orig_connect          connect
  alias orig_sysaccept        sysaccept
  # :startdoc:
  
  include IPSocketAccess
  
  def initialize(*args)
    @acl = nil
    orig_initialize(*args)
    return self
  end
  
  # accept on steroids.
  def accept(*args)
    acl = @acl || IPAccess::Global
    ret = orig_accept(*args)
    acl.check_in_socket(ret.first)
    return ret
  end
  
  # accept_nonblock on steroids.
  def accept_nonblock(*args)
    acl = @acl || IPAccess::Global
    ret = orig_accept_nonblock(*args)
    acl.check_in_socket(ret.first)
    return ret
  end
  
  # sysaccept on steroids.
  def sysaccept(*args)
    acl = @acl || IPAccess::Global
    ret = orig_accept(*args)
    acl.check_in_sockaddr(ret.last)
    return ret
  end

  # connect on steroids.
  def connect(*args)
    acl = @acl || IPAccess::Global
    acl.check_out_sockaddr(args.first)
    return orig_connect(*args)
  end
  
end


