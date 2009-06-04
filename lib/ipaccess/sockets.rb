# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of GNU Lesser General Public License or Ruby License.
# 
# Classes contained in this file are subclasses
# of Ruby socket handling classes equipped
# with IP access control.
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
require 'ipaccess/ip_access'
require 'ipaccess/ip_access_patches'

######################################################
# Socket class with IP access control.
# It uses input access lists.
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

class IPAccess::Socket < Socket
  include IPAccess::Patches::Socket
end

######################################################
# UDPSocket class with IP access control.
# It uses input access lists.
#
# This acts the same way as UDPSocket class but
# provides special member called +acl+ for
# controlling IP access.

class IPAccess::UDPSocket < UDPSocket
  include IPAccess::Patches::UDPSocket
end

if Object.const_defined?(:SOCKSSocket)
  ######################################################
  # SOCKSSocket class with IP access control.
  # It uses input access lists.
  # 
  # This acts the same way as SOCKSSocket class but
  # provides special member called +acl+ for
  # controlling IP access.
  
  class IPAccess::SOCKSSocket < SOCKSSocket
    include IPAccess::Patches::SOCKSSocket
  end
end

######################################################
# TCPSocket class with IP access control.
# It uses output access lists.
#
# This acts the same way as TCPSocket class but
# provides special member called +acl+ for
# controlling IP access.
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
  include IPAccess::Patches::TCPSocket
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
#     serv.acl = :private                           # create and use private access lists
#     serv.acl.input.block :local, :private         # block local and private addresses
#     serv.acl.input.permit '127.0.0.5'             # make an exception
#     
#     puts serv.acl.input.blacklist                 # show blacklisted IP addresses
#     puts serv.acl.input.whitelist                 # show whitelisted IP addresses
#     
#     sock = serv.sysaccept                         # accept connection

class IPAccess::TCPServer < TCPServer
  include IPAccess::Patches::TCPServer
end

