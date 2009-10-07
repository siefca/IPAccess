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
# Socket[http://www.ruby-doc.org/core/classes/Socket.html]
# class with IP access control.
# It uses input and output access lists. Default
# list for methods that deal with rules is +output+.
#
# This class acts the same way as Socket[http://www.ruby-doc.org/core/classes/Socket.html] 
# class but provides special member called +acl+ and a few new
# instance methods for controlling IP access.
#
#:include:ghost_doc_patched_usage.rb
# 
# This documentation doesn't cover description of all
# class and instance methods of the original
# Socket[http://www.ruby-doc.org/core/classes/Socket.html]
# class, just the patched variants that make use of IP access control.
#
# === Example
#     
#     require 'socket'                                        # load native sockets
#     require 'ipaccess/socket'                               # load sockets subsystem and IPAccess.arm method
#     include Socket::Constants
#     
#     IPAccess::Set.Global.input.blacklist :localhost             # add localhost to global access set
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
  #:include:ghost_doc_p_whitelist_e.rb
  def whitelist!; end

  #:include:ghost_doc_p_whitelist.rb
  def whitelist; end

  #:include:ghost_doc_p_blacklist_e.rb
  def blacklist!; end

  #:include:ghost_doc_p_blacklist.rb
  def blacklist; end

  #:include:ghost_doc_p_unwhitelist_e.rb
  def unwhitelist!; end
  
  #:include:ghost_doc_p_unwhitelist.rb
  def unwhitelist; end

  #:include:ghost_doc_p_unblacklist_e.rb
  def unblacklist!; end

  #:include:ghost_doc_p_unblacklist.rb
  def unblacklist; end

  alias_method :unblock!,   :unblacklist!
  alias_method :del_black!, :unblacklist!
  alias_method :unblock,    :unblacklist
  alias_method :del_black,  :unblacklist
  alias_method :add_black!, :blacklist!
  alias_method :deny!,      :blacklist!
  alias_method :block!,     :blacklist!
  alias_method :add_black,  :blacklist
  alias_method :deny,       :blacklist
  alias_method :block,      :blacklist
  alias_method :del_white!, :unwhitelist!
  alias_method :del_white,  :unwhitelist
  
  #:include:ghost_doc_acl.rb
  #  
  # === Example
  #
  #     require 'ipaccess/socket'   # load sockets subsystem
  # 
  #     socket = IPAccess::Socket.new(AF_INET, SOCK_STREAM, 0)
  #     socket.acl = :global        # use global access set
  #     socket.acl = :private       # create and use individual access set
  #     socket.acl = IPAccess::Set.new   # use external (shared) access set
  
  attr_writer :acl
  
  # This member keeps the information about currently
  # used access set. You may use it to do low-level
  # operations on IPAccess::Set object associated
  # with instance. You cannot however call any
  # of global access set operations – to do that
  # use IPAccess::Set.Global contant referencing to
  # global ACL.
  
  attr_reader :acl
  
end

######################################################
# UDPSocket[http://www.ruby-doc.org/core/classes/UDPSocket.html]
# class with IP access control. It uses input and output
# access lists. Default list for rules management
# methods is +input+.
#
# This class acts the same way as UDPSocket[http://www.ruby-doc.org/core/classes/UDPSocket.html] 
# class but provides special member called +acl+ and a few new
# instance methods for controlling IP access.
#
#:include:ghost_doc_patched_usage.rb
# 
# This documentation doesn't cover description of all
# class and instance methods of the original
# UDPSocket[http://www.ruby-doc.org/core/classes/UDPSocket.html] 
# class, just the patched variants that make use of IP access control.

class IPAccess::UDPSocket
  #:include:ghost_doc_p_whitelist_e.rb
  def whitelist!; end

  #:include:ghost_doc_p_whitelist.rb
  def whitelist; end

  #:include:ghost_doc_p_blacklist_e.rb
  def blacklist!; end

  #:include:ghost_doc_p_blacklist.rb
  def blacklist; end

  #:include:ghost_doc_p_unwhitelist_e.rb
  def unwhitelist!; end
  
  #:include:ghost_doc_p_unwhitelist.rb
  def unwhitelist; end

  #:include:ghost_doc_p_unblacklist_e.rb
  def unblacklist!; end

  #:include:ghost_doc_p_unblacklist.rb
  def unblacklist; end

  alias_method :unblock!,   :unblacklist!
  alias_method :del_black!, :unblacklist!
  alias_method :unblock,    :unblacklist
  alias_method :del_black,  :unblacklist
  alias_method :add_black!, :blacklist!
  alias_method :deny!,      :blacklist!
  alias_method :block!,     :blacklist!
  alias_method :add_black,  :blacklist
  alias_method :deny,       :blacklist
  alias_method :block,      :blacklist
  alias_method :del_white!, :unwhitelist!
  alias_method :del_white,  :unwhitelist
  
  #:include:ghost_doc_acl.rb
  #  
  # === Example
  #     
  #     require 'ipaccess/socket'   # load sockets subsystem
  #      
  #     socket = IPAccess::UDPSocket.new
  #     socket.acl = :global        # use global access set
  #     socket.acl = :private       # create and use individual access set
  #     socket.acl = IPAccess::Set.new   # use external (shared) access set
  
  attr_writer :acl
  
  # This member keeps the information about currently
  # used access set. You may use it to do low-level
  # operations on IPAccess::Set object associated
  # with instance. You cannot however call any
  # of global access set operations – to do that
  # use IPAccess::Set.Global contant referencing to
  # global ACL.
  
  attr_reader :acl

end

######################################################
# SOCKSSocket[http://www.ruby-doc.org/core/classes/SOCKSSocket.html]
# class with IP access control. It uses +output+ access lists.
# 
# This class acts the same way as SOCKSSocket[http://www.ruby-doc.org/core/classes/SOCKSSocket.html] 
# class but provides special member called +acl+ and a few new
# instance methods for controlling IP access.
#
#:include:ghost_doc_patched_usage.rb
# 
# This documentation doesn't cover description of all
# class and instance methods of the original
# SOCKSSocket[http://www.ruby-doc.org/core/classes/SOCKSSocket.html] 
# class, just the patched variants that make use of IP access control.

class IPAccess::SOCKSSocket
  #:include:ghost_doc_p_whitelist_e.rb
  def whitelist!; end

  #:include:ghost_doc_p_whitelist.rb
  def whitelist; end

  #:include:ghost_doc_p_blacklist_e.rb
  def blacklist!; end

  #:include:ghost_doc_p_blacklist.rb
  def blacklist; end

  #:include:ghost_doc_p_unwhitelist_e.rb
  def unwhitelist!; end
  
  #:include:ghost_doc_p_unwhitelist.rb
  def unwhitelist; end

  #:include:ghost_doc_p_unblacklist_e.rb
  def unblacklist!; end

  #:include:ghost_doc_p_unblacklist.rb
  def unblacklist; end

  alias_method :unblock!,   :unblacklist!
  alias_method :del_black!, :unblacklist!
  alias_method :unblock,    :unblacklist
  alias_method :del_black,  :unblacklist
  alias_method :add_black!, :blacklist!
  alias_method :deny!,      :blacklist!
  alias_method :block!,     :blacklist!
  alias_method :add_black,  :blacklist
  alias_method :deny,       :blacklist
  alias_method :block,      :blacklist
  alias_method :del_white!, :unwhitelist!
  alias_method :del_white,  :unwhitelist
  
  #:include:ghost_doc_acl.rb
  #  
  # === Example
  #
  #     require 'ipaccess/socket'                                           # load sockets subsystem
  # 
  #     acl_set = IPAccess::Set.new                                              # create shared access set
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
  
  attr_writer :acl

  # This member keeps the information about currently
  # used access set. You may use it to do low-level
  # operations on IPAccess::Set object associated
  # with instance. You cannot however call any
  # of global access set operations – to do that
  # use IPAccess::Set.Global contant referencing to
  # global ACL.
  
  attr_reader :acl

end

######################################################
# TCPSocket[http://www.ruby-doc.org/core/classes/TCPSocket.html]
# class with IP access control. It uses +output+
# access lists.
# 
# This class acts the same way as
# TCPSocket[http://www.ruby-doc.org/core/classes/TCPSocket.html]
# class but provides special member called +acl+ and a few new
# instance methods for controlling IP access.
#
#:include:ghost_doc_patched_usage.rb
# 
# This documentation doesn't cover description of all
# class and instance methods of the original
# TCPSocket[http://www.ruby-doc.org/core/classes/TCPSocket.html]
# class, just the patched variants that make use of IP access control.
# 
# === Example
# 
#     require 'ipaccess/socket'                                         # load sockets subsystem
#     
#     acl_set = IPAccess::Set.new                                            # create shared access set
#     acl_set.output.block 'randomseed.pl'                              # block connections to this host
#     
#     socket = IPAccess::TCPSocket.new('randomseed.pl', 80)

class IPAccess::TCPSocket
  #:include:ghost_doc_p_whitelist_e.rb
  def whitelist!; end

  #:include:ghost_doc_p_whitelist.rb
  def whitelist; end

  #:include:ghost_doc_p_blacklist_e.rb
  def blacklist!; end

  #:include:ghost_doc_p_blacklist.rb
  def blacklist; end

  #:include:ghost_doc_p_unwhitelist_e.rb
  def unwhitelist!; end
  
  #:include:ghost_doc_p_unwhitelist.rb
  def unwhitelist; end

  #:include:ghost_doc_p_unblacklist_e.rb
  def unblacklist!; end

  #:include:ghost_doc_p_unblacklist.rb
  def unblacklist; end

  alias_method :unblock!,   :unblacklist!
  alias_method :del_black!, :unblacklist!
  alias_method :unblock,    :unblacklist
  alias_method :del_black,  :unblacklist
  alias_method :add_black!, :blacklist!
  alias_method :deny!,      :blacklist!
  alias_method :block!,     :blacklist!
  alias_method :add_black,  :blacklist
  alias_method :deny,       :blacklist
  alias_method :block,      :blacklist
  alias_method :del_white!, :unwhitelist!
  alias_method :del_white,  :unwhitelist
  
  #:include:ghost_doc_acl.rb
  # 
  # === Example
  # 
  #     require 'ipaccess/socket'                                         # load sockets subsystem
  #     
  #     acl_set = IPAccess::Set.new                                            # create shared access set
  #     acl_set.output.block 'randomseed.pl'                              # block connections to this host
  #     
  #     socket = IPAccess::TCPSocket.new('randomseed.pl', 80)             # use global access set
  #     socket = IPAccess::TCPSocket.new('randomseed.pl', 80, acl_set)    # use shared access set
  #
  # Because SOCKSSocket objects tend to open connection when
  # are created you have to assign access set in the very moment
  # of initialization. Note that using private access set is
  # possible but useles in this case.
  
  attr_writer :acl
  
  # This member keeps the information about currently
  # used access set. You may use it to do low-level
  # operations on IPAccess::Set object associated
  # with instance. You cannot however call any
  # of global access set operations – to do that
  # use IPAccess::Set.Global contant referencing to
  # global ACL.
  
  attr_reader :acl

end


######################################################
# TCPServer[http://www.ruby-doc.org/core/classes/TCPServer.html]
# class with IP access control. It uses +input+
# access lists.
# 
# This class acts the same way as
# TCPServer[http://www.ruby-doc.org/core/classes/TCPServer.html]
# class but provides special member called +acl+ and a few new
# instance methods for controlling IP access.
#
#:include:ghost_doc_patched_usage.rb
# 
# This documentation doesn't cover description of all
# class and instance methods of the original
# TCPServer[http://www.ruby-doc.org/core/classes/TCPServer.html]
# class, just the patched variants that make use of IP access control.
# 
# === Example
#     
#     require 'ipaccess/socket'                 # load sockets subsystem
#     
#     serv = IPAccess::TCPServer.new(31337)     # create listening TCP socket
#     serv.acl = :private                       # create and use private access set
#     serv.blacklist :local, :private           # block local and private IP addresses
#     serv.permit '127.0.0.5'                   # make an exception
#     
#     puts serv.acl.show                        # show listed IP addresses
#     
#     sock = serv.sysaccept                     # accept connection

class IPAccess::TCPServer
  #:include:ghost_doc_p_whitelist_e.rb
  def whitelist!; end

  #:include:ghost_doc_p_whitelist.rb
  def whitelist; end

  #:include:ghost_doc_p_blacklist_e.rb
  def blacklist!; end

  #:include:ghost_doc_p_blacklist.rb
  def blacklist; end

  #:include:ghost_doc_p_unwhitelist_e.rb
  def unwhitelist!; end
  
  #:include:ghost_doc_p_unwhitelist.rb
  def unwhitelist; end

  #:include:ghost_doc_p_unblacklist_e.rb
  def unblacklist!; end

  #:include:ghost_doc_p_unblacklist.rb
  def unblacklist; end

  alias_method :unblock!,   :unblacklist!
  alias_method :del_black!, :unblacklist!
  alias_method :unblock,    :unblacklist
  alias_method :del_black,  :unblacklist
  alias_method :add_black!, :blacklist!
  alias_method :deny!,      :blacklist!
  alias_method :block!,     :blacklist!
  alias_method :add_black,  :blacklist
  alias_method :deny,       :blacklist
  alias_method :block,      :blacklist
  alias_method :del_white!, :unwhitelist!
  alias_method :del_white,  :unwhitelist
  
  #:include:ghost_doc_acl.rb
  #  
  # === Example
  # 
  #     require 'ipaccess/socket'                 # load sockets subsystem
  #     
  #     socket = IPAccess::TCPServer.new(31337)   # create TCP server
  #     socket.acl = :global                      # use global access set
  #     socket.acl = :private                     # create and use individual access set
  #     socket.acl = IPAccess::Set.new                 # use external (shared) access set
  
  attr_writer :acl
  
  # This member keeps the information about currently
  # used access set. You may use it to do low-level
  # operations on IPAccess::Set object associated
  # with instance. You cannot however call any
  # of global access set operations – to do that
  # use IPAccess::Set.Global contant referencing to
  # global ACL.
  
  attr_reader :acl

end
