# encoding: utf-8
#
# Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This is licensed under LGPL or Ruby License.
# 
# === sockets
# 
# Classes contained in this file are subclasses
# of Ruby socket handling classes equipped
# with IP access control.

$LOAD_PATH.unshift '..'

require 'socket'
require 'ipaccess'
require 'ipaccess/ip_access_patches'

######################################################
# Socket class with IP access control.
# It uses input access lists.
#
# This acts same as Socket class but provides special
# member called +acl+ for controlling IP access.
# 
# ==== Example
#     require 'ipaddr/sockets'
#     include Socket::Constants
#     
#     IPAccess::Global.input.blacklist :localhost             # add localhost to global access set
#                                                             # as a black rule of input list
#     socket = IPAccess::Socket.new(AF_INET, SOCK_STREAM, 0)  # create TCP socket
#     sockaddr = Socket.sockaddr_in(31337, '127.0.0.1')       # create sockadr_in structure
#     socket.bind(sockaddr)                                   # bind to port 31331 and IP 127.0.0.1
#     socket.listen(5)                                        # listen on socket
#     begin
#       c_socket, c_sockaddr = socket.accept_nonblock         # call non-blocking accept for connections
#     rescue Errno::EAGAIN, Errno::ECONNABORTED,
#            Errno::EPROTO, Errno::EINTR                  
#       IO.select([socket])                                   # retry on retriable errors
#       retry
#     rescue IPAccessDenied                                   # when access is denied
#       c_socket.close                                        # close client socket
#       socket.close                                          # close listener
#       raise                                                 # raise exception
#     end
#     c_socket.puts "Hello world!"                            # otherwise continue
#     c_socket.close
#     socket.close

class IPAccess::Socket < Socket
  # This method selects IPAccess object that will be used to
  # control IP access for a socket. You may assign global access set,
  # create local access set or use shared set.
  # 
  # If argument is an IPAccess object then it is used.
  # If argument is other kind it is assumed that it
  # should be converted to IPAccess object (initial arguments
  # are considered to be IP rules for a black list). If argument
  # is +:global+ it uses global access set. If argument is +:local+
  # it creates an empty, private access set.
  # 
  # ==== Example
  #
  #     socket.acl = :global        # use global access set
  #     socket.acl = :local         # create and use local access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=; end
  
  # This method allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  def acl; end
  
  include IPAccess::Patches::Socket
end

######################################################
# UDPSocket class with IP access control.
# It uses input access lists.

class IPAccess::UDPSocket < UDPSocket
  # This method selects IPAccess object that will be used to
  # control IP access for a socket. You may assign global access set,
  # create local access set or use shared set.
  # 
  # If argument is an IPAccess object then it is used.
  # If argument is other kind it is assumed that it
  # should be converted to IPAccess object (initial arguments
  # are considered to be IP rules for a black list). If argument
  # is +:global+ it uses global access set. If argument is +:local+
  # it creates an empty, private access set.
  # 
  # ==== Example
  #
  #     socket.acl = :global        # use global access set
  #     socket.acl = :local         # create and use local access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=; end
  
  # This method allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  def acl; end
  
  include IPAccess::Patches::UDPSocket
end

if Object.const_defined?(:SOCKSSocket)
  ######################################################
  # SOCKSSocket class with IP access control.
  # It uses input access lists.
  class IPAccess::SOCKSSocket < SOCKSSocket
    # This method selects IPAccess object that will be used to
    # control IP access for a socket. You may assign global access set,
    # create local access set or use shared set.
    # 
    # If argument is an IPAccess object then it is used.
    # If argument is other kind it is assumed that it
    # should be converted to IPAccess object (initial arguments
    # are considered to be IP rules for a black list). If argument
    # is +:global+ it uses global access set. If argument is +:local+
    # it creates an empty, private access set.
    # 
    # ==== Example
    #
    #     socket.acl = :global        # use global access set
    #     socket.acl = :local         # create and use local access set
    #     socket.acl = IPAccess.new   # use external (shared) access set
    def acl=; end

    # This method allows you to manipulate local and shared access sets
    # associated with this socket. To control global access set use
    # IPAccess::Global
    def acl; end
    
    include IPAccess::Patches::SOCKSSocket
  end
end

######################################################
# TCPSocket class with IP access control.
# It uses output access lists.
#
# ==== Example
#     require 'ipaddr/sockets'
#     
#     list = IPAccess.new 'my list'                     # use external access lists
#     list.output.block '1.2.3.4/16'                    # block connections to 1.2.0.0/16
#     list.output.block 'randomseed.pl'                 # block connections to IP address of randomseed.pl
#     socket = IPAccess::TCPSocket.new('randomseed.pl', # create connected TCP socket with access control
#                                       80, list)
# 
# Note that in this example we cannot alter
# access list after creating socket since
# TCPSocket instance does connect at the very
# beginning of existence.

class IPAccess::TCPSocket < TCPSocket
  # This method selects IPAccess object that will be used to
  # control IP access for a socket. You may assign global access set,
  # create local access set or use shared set.
  # 
  # If argument is an IPAccess object then it is used.
  # If argument is other kind it is assumed that it
  # should be converted to IPAccess object (initial arguments
  # are considered to be IP rules for a black list). If argument
  # is +:global+ it uses global access set. If argument is +:local+
  # it creates an empty, private access set.
  # 
  # ==== Example
  #
  #     socket.acl = :global        # use global access set
  #     socket.acl = :local         # create and use local access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=; end
  
  # This method allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  def acl; end
    
  include IPAccess::Patches::TCPSocket
end

######################################################
# TCPServer class with IP access control.
# It uses input access lists.
#
# ==== Example
#     require 'ipaddr/sockets'
#     
#     serv = IPAccess::TCPServer.new(31337)         # create listening TCP socket
#     serv.acl = :local                             # create and use local access lists
#     serv.acl.input.block :local, :private         # block local and private addresses
#     serv.acl.input.permit '127.0.0.5'             # make an exception
#     
#     puts serv.acl.input.blacklist                 # show blacklisted IP addresses
#     puts serv.acl.input.whitelist                 # show whitelisted IP addresses
#     
#     sock = serv.sysaccept                         # accept connection

class IPAccess::TCPServer < TCPServer
  # This method selects IPAccess object that will be used to
  # control IP access for a socket. You may assign global access set,
  # create local access set or use shared set.
  # 
  # If argument is an IPAccess object then it is used.
  # If argument is other kind it is assumed that it
  # should be converted to IPAccess object (initial arguments
  # are considered to be IP rules for a black list). If argument
  # is +:global+ it uses global access set. If argument is +:local+
  # it creates an empty, private access set.
  # 
  # ==== Example
  #
  #     socket.acl = :global        # use global access set
  #     socket.acl = :local         # create and use local access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=; end
  
  # This method allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  def acl; end
  
  include IPAccess::Patches::TCPServer
end



