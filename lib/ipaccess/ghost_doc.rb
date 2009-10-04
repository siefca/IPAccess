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
# === Example
#     
#     require 'socket'                                        # load native sockets
#     require 'ipaccess/socket'                               # load sockets subsystem and IPAccess.arm method
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
  # === Example
  #
  #     require 'ipaccess/socket'   # load sockets subsystem
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
  # === Example
  #     
  #     require 'ipaccess/socket'   # load sockets subsystem
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
  # === Example
  #
  #     require 'ipaccess/socket'                                           # load sockets subsystem
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
# 
# === Example
# 
#     require 'ipaccess/socket'                                         # load sockets subsystem
#     
#     acl_set = IPAccess.new                                            # create shared access set
#     acl_set.output.block 'randomseed.pl'                              # block connections to this host
#     
#     socket = IPAccess::TCPSocket.new('randomseed.pl', 80)

class IPAccess::TCPSocket
  #:include:ghost_doc_acl.rb
  # 
  # === Example
  # 
  #     require 'ipaccess/socket'                                         # load sockets subsystem
  #     
  #     acl_set = IPAccess.new                                            # create shared access set
  #     acl_set.output.block 'randomseed.pl'                              # block connections to this host
  #     
  #     socket = IPAccess::TCPSocket.new('randomseed.pl', 80)             # use global access set
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
# === Example
#     
#     require 'ipaccess/socket'                     # load sockets subsystem
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
  # === Example
  # 
  #     require 'ipaccess/socket'                 # load sockets subsystem
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

######################################################
# Net::HTTP[http://www.ruby-doc.org/stdlib/libdoc/net/http/rdoc/classes/Net/HTTP.html]
# class with IP access control. It uses output access lists
# and acts the same way as Net::HTTP class but
# provides special member called +acl+ for
# controlling IP access. Access checks are lazy
# which means they are performed when real connection
# is going to happend. Instances of this class will also
# internally use patched versions of Ruby's network
# socket objects to avoid access leaks.
# 
# You can pass access set in various ways: while
# creating HTTP object or while starting HTTP session.
# You can also rely on global access set.
#
# === Usage
# 
# There are 3 ways to enable access control:
#
# * patching Net::HTTP[http://www.ruby-doc.org/stdlib/libdoc/net/http/rdoc/classes/Net/HTTP.html] class (see IPAccess.arm) – use it in code you cannot easily modify
# * patching single instance (see IPAccess.arm) – use it occasionally
# * using IPAccess::Net::HTTP class – use it in your own code
# 
# This documentation doesn't cover description of all
# class and instance methods of the original
# Net::HTTP[http://www.ruby-doc.org/stdlib/libdoc/net/http/rdoc/classes/Net/HTTP.html]
# class, just the patched variants that make use of IP access control.
# 
# === Examples
#
# ==== Simple method, shared access set
#
#     require 'ipaccess/net/http'
#     
#     # blacklist randomseed.pl in global access set
#     IPAccess::Global.output.blacklist 'randomseed.pl'
#     
#     # call get_print
#     IPAccess::Net::HTTP.get_print 'randomseed.pl', '/index.html'
# 
# ==== Simple method, shared access set
#
#     require 'ipaccess/net/http'
#     
#     # create access set
#     acl = IPAccess.new
#     
#     # blacklist randomseed.pl in shared access set
#     acl.output.blacklist 'randomseed.pl'
#     
#     call get_print with shared access set passed
#     IPAccess::Net::HTTP.get_print 'randomseed.pl', '/index.html', acl
# 
# ==== Class method start, shared access set 
#
#     require 'ipaccess/net/http'
#     require 'uri'
#     
#     # create access set
#     acl = IPAccess.new
#     
#     # blacklist randomseed.pl in shared access set
#     acl.output.blacklist 'randomseed.pl'
#     
#     # parse URI
#     url = URI.parse('http://randomseed.pl/index.html')
#     
#     # call start passing shared access set
#     res = IPAccess::Net::HTTP.start(url.host, url.port, acl) { |http|
#       http.get("/")
#     }
# 
# ==== Generic method, private access set
# 
#     require 'ipaccess/net/http'
#     
#     # create new GET request
#     req = Net::HTTP::Get.new('/index.html')           
#     
#     htt = IPAccess::Net::HTTP.new('randomseed.pl',        # create Net::HTTP variant
#                                   80,                     
#                                   :private)               # with private access set
#     
#     htt.acl.output.blacklist 'randomseed.pl'              # blacklist randomseed.pl
#     res = htt.start { |http|                              # start HTTP session
#       http.request(req)                                   # and send the request
#     }
#
# ==== Generic method, shared access set, single object patched
#
#     require 'ipaccess/net/http'
#     
#     # create custom access set with one blacklisted IP
#     acl = IPAccess.new
#     acl.output.blacklist 'randomseed.pl'
#     
#     # create HTTP request and Net::HTTP object
#     req = Net::HTTP::Get.new("/")
#     htt = Net::HTTP.new(url.host, url.port)
#     
#     # patch newly created object
#     IPAccess.arm htt, acl
#     
#     # start HTTP session
#     res = htt.start { |http|
#       http.request(req)
#     }
#
# ==== Simple method, shared access set, class patched
#
#     require 'ipaccess/net/http'
#     
#     # blacklist randomseed.pl in shared access set
#     acl = IPAccess.new
#     acl.output.blacklist 'randomseed.pl'
#     
#     # patch whole Net::HTTP class
#     IPAccess.arm Net::HTTP
#     
#     # call get_print with passed access set
#     Net::HTTP.get_print 'randomseed.pl', '/index.html', acl
#

class IPAccess::Net::HTTP
  
  #:include:ghost_doc_acl.rb
  #  
  # === Example
  # 
  #     require 'ipaccess/net/http'                         # load Net::HTTP variant
  #     
  #     http = IPAccess::Net::HTTP.new('randomseed.pl', 80) # create HTTP object
  # 
  #     http.acl = :global                      # use global access set
  #     http.acl = :private                     # create and use individual access set
  #     http.acl = IPAccess.new                 # use external (shared) access set

  attr_reader :acl

  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  
  attr_writer :acl

  # This method allows you to re-check access on demad.
  # It uses internal socket's address and access set assigned
  # to an object.
  
  def acl_recheck
    # Real code hidden.
  end
  
  # :call-seq:
  #   new(address)<br />
  #   new(address, acl) <br />
  #   new(address, port, acl)
  # 
  # Creates a new object for the specified address.
  # This method does not open the TCP connection.
  # It optionally sets an access set given as the
  # last parameter. If parameter is not given it
  # sets ACL to IPAccess::Global.
  
  def initialize
    # Real code hidden.
  end

  # :call-seq:
  #   start(address, port, p_addr, p_port, p_user, p_pass, acl) |<tt>http</tt>|<br />
  #   start(address, port , p_addr, p_port, acl) |<tt>http</tt>|<br />
  #   start(address, port, p_addr, acl) |<tt>http</tt>|<br />
  #   start(address, port, acl) |<tt>http</tt>|<br />
  #   start(address, acl) |<tt>http</tt>|<br />
  #   start(address, port = nil, p_addr = nil, p_port = nil, p_user = nil, p_pass = nil) |<tt>http</tt>|
  #
  # Creates a new object and opens its TCP connection
  # and HTTP session. If the optional block is given,
  # the newly created Net::HTTP object is passed to it
  # and closed when the block finishes. In this case,
  # the return value of this method is the return value
  # of the block. If no block is given, the return value of this
  # method is the newly created Net::HTTP object itself,
  # and the caller is responsible for closing it upon
  # completion. It optionally sets an access set given
  # as the last parameter. If parameter is not given
  # it sets ACL to IPAccess::Global.
  
  def self.start
    # Real code hidden.
  end

  # :call-seq:
  #   start(uri_or_host, path, port, acl) |<tt>http</tt>|<br />
  #   start(uri_or_host, path, acl) |<tt>http</tt>|<br />
  #   start(uri_or_host, acl) |<tt>http</tt>|<br />
  #   start(uri_or_host, path = nil, port = nil) |<tt>http</tt>|
  #   
  # Sends a GET request to the target and return the response as a Net::HTTPResponse object.
  # The target can either be specified as (uri), or as
  # (host, path, port = 80).
  # It optionally sets an access set given as the
  # last parameter. If parameter is not given it
  # sets ACL to IPAccess::Global.
  
  def self.get_response
    # Real code hidden.
  end
  
end


class IPAccess::Net::Telnet
  #:include:ghost_doc_acl.rb
  #  
  # === Example
  # 
  #     require 'ipaccess/net/telnet'             # load Net::Telnet variant
  #     
  #     opts = {}
  #     opts["Host"] = 'randomseed.pl'
  #     opts["ACL"] = IPAccess.new                # shared ACL
  #     telnet = IPAccess::Net::Telnet.new(opts)  # create connected Telnet object
  # 
  #     telnet.acl = :global                      # use global access set
  #     telnet.acl = :private                     # create and use individual access set
  #     telnet.acl = IPAccess.new                 # use external (shared) access set

  def acl=(set); end
  
  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global

  attr_reader :acl
  
end

