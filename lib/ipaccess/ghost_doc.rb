# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:LGPL-LICENSE.html] or Ruby License.
# 
# Classes contained are just for documentary purposes.
# It is a scaffold for keeping virtual methods that
# cannot be detected by RDoc.
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
 

######################################################
# Socket class with IP access control.
# It uses input and output access lists.
#
# This acts the same way as Socket class but
# provides special member called +acl+ for
# controlling IP access.
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
# 
class IPAccess::Socket
  #:include:ghost_doc_acl.rb
  #  
  # ==== Example
  # 
  #     socket = IPAccess::Socket.new(AF_INET, SOCK_STREAM, 0)
  #     socket.acl = :global        # use global access set
  #     socket.acl = :private       # create and use individual access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=(set); end
  
  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  attr_reader :acl

end

######################################################
# UDPSocket class with IP access control.
# It uses input access lists.
#
# This acts the same way as UDPSocket class but
# provides special member called +acl+ for
# controlling IP access.

class IPAccess::UDPSocket
  #:include:ghost_doc_acl.rb
  #  
  # ==== Example
  # 
  #     socket = IPAccess::UDPSocket.new
  #     socket.acl = :global        # use global access set
  #     socket.acl = :private       # create and use individual access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=(set); end
  
  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  attr_reader :acl

end

######################################################
# SOCKSSocket class with IP access control.
# It uses input access lists.
# 
# This acts the same way as SOCKSSocket class but
# provides special member called +acl+ for
# controlling IP access.

class IPAccess::SOCKSSocket
  #:include:ghost_doc_acl.rb
  #  
  # ==== Example
  # 
  #     acl_set = IPAccess.new                                              # create shared access set
  #     acl_set.output.block 'randomseed.pl'                                # block connections to this host
  #     
  #     socket = IPAccess::SOCKSSocket.new('randomseed.pl', 80)             # use global access set
  #     socket = IPAccess::SOCKSSocket.new('randomseed.pl', 80, :private)   # use private access set (!?!)
  #     socket = IPAccess::SOCKSSocket.new('randomseed.pl', 80, acl_set)    # use shared access set
  #
  # Because SOCKSSocket objects tend to open connection when
  # are created you have to assign access set in the very moment
  # of initialization. Note that using private access set is
  # possible but useles in this case.
  def acl=(set); end

  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  attr_reader :acl

end

######################################################
# TCPSocket class with IP access control.
# It uses output access lists.
#
# This acts the same way as TCPSocket class but
# provides special member called +acl+ for
# controlling IP access.

class IPAccess::TCPSocket
  #:include:ghost_doc_acl.rb
  #  
  # ==== Example
  # 
  #     acl_set = IPAccess.new                                            # create shared access set
  #     acl_set.output.block 'randomseed.pl'                              # block connections to this host
  #     
  #     socket = IPAccess::TCPSocket.new('randomseed.pl', 80)             # use global access set
  #     socket = IPAccess::TCPSocket.new('randomseed.pl', 80, :private)   # use private access set (!?!)
  #     socket = IPAccess::TCPSocket.new('randomseed.pl', 80, acl_set)    # use shared access set
  #
  # Because SOCKSSocket objects tend to open connection when
  # are created you have to assign access set in the very moment
  # of initialization. Note that using private access set is
  # possible but useles in this case.
  def acl=(set); end
  
  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  attr_reader :acl
  
end

######################################################
# TCPServer class with IP access control.
# It uses input access lists.
# 
# This acts the same way as TCPServer class but
# provides special member called +acl+ for
# controlling IP access.
# 
# ==== Example
#     require 'ipaddr/sockets'
#     
#     serv = IPAccess::TCPServer.new(31337)         # create listening TCP socket
#     serv.acl = :private                           # create and use private access set
#     serv.acl.input.block :local, :private         # block local and private addresses
#     serv.acl.input.permit '127.0.0.5'             # make an exception
#     
#     puts serv.acl.input.blacklist                 # show blacklisted IP addresses
#     puts serv.acl.input.whitelist                 # show whitelisted IP addresses
#     
#     sock = serv.sysaccept                         # accept connection

class IPAccess::TCPServer
  #:include:ghost_doc_acl.rb
  #  
  # ==== Example
  # 
  #     socket = IPAccess::TCPServer.new(31337)   # create TCP server
  #     socket.acl = :global                      # use global access set
  #     socket.acl = :private                     # create and use individual access set
  #     socket.acl = IPAccess.new                 # use external (shared) access set
  def acl=(set); end
  
  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  attr_reader :acl
  
end

