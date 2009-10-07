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
# Net::Telnet[http://www.ruby-doc.org/stdlib/libdoc/net/telnet/rdoc/classes/Net/Telnet.html]
# class with IP access control. It uses output access lists
# and acts the same way as Net::Telnet class but
# provides provides special member called +acl+ and a few new
# instance methods for controlling IP access.
# 
#:include:ghost_doc_patched_usage.rb
# 
# This documentation doesn't cover description of all
# class and instance methods of the original
# Net::Telnet[http://www.ruby-doc.org/stdlib/libdoc/net/telnet/rdoc/classes/Net/Telnet.html]
# class, just the patched variants that make use of IP access control.
# 
# === Examples
# 
# ==== Global access set, using IPAccess::Net::Telnet
# 
#     require 'ipaccess/net/telnet'         # load Net::Telnet version and IPAccess.arm method
#     
#     opts = {}               
#     opts["Host"]  = 'randomseed.pl'   
#     opts["Port"]  = '80'
#     
#     IPAccess::Set.Global.output.blacklist 'randomseed.pl' # blacklist host
#     t = IPAccess::Net::Telnet.new(opts)               # try to connect to remote host                                       
# 
# ==== Global access set, single object patched, direct blacklisting
# 
#     require 'ipaccess/net/telnet'     # load Net::Telnet version and IPAccess.arm method
#     
#     opts = {}
#     opts["Host"]  = 'randomseed.pl'
#     opts["Port"]  = '80'
#     
#     t = Net::Telnet.new(opts)       # try to connect to remote host
#     IPAccess.arm t                  # arm single Telnet object (will use global access set)
#     t.blacklist! 'randomseed.pl'    # blacklist host while being connected
# 
# ==== Shared access set, single object patched
# 
#     require 'ipaccess/net/telnet'         # load Net::Telnet version and IPAccess.arm method
#                                        
#     opts = {}                          
#     opts["Host"]  = 'randomseed.pl'    
#     opts["Port"]  = '80'               
#                                        
#     t = Net::Telnet.new(opts)             # try to connect to remote host
#                                        
#     acl = IPAccess::Set.new                    # create custom access set
#     acl.output.blacklist 'randomseed.pl'  # blacklist host in access set
#     IPAccess.arm t, acl                   # arm single Telnet object with access set passed
# 
# ==== Shared access set, single object patched, direct blacklisting
# 
#     require 'ipaccess/net/telnet'         # load Net::Telnet version and IPAccess.arm method
#                                        
#     opts = {}                          
#     opts["Host"]  = 'randomseed.pl'
#     opts["Port"]  = '80'               
#                                        
#     t = Net::Telnet.new(opts)             # try to connect to remote host
#                                        
#     acl = IPAccess::Set.new                    # create custom access set
#     IPAccess.arm t, acl                   # arm single Telnet object with access set passed
#     t.blacklist 'randomseed.pl'           # blacklist host 
#
# ==== Shared access set, class patched
#                                        
#     require 'ipaccess/net/telnet'         # load Net::Telnet version and IPAccess.arm method
#     
#     opts = {}
#     opts["Host"]  = 'randomseed.pl'
#     opts["Port"]  = '80'
#     
#     IPAccess.arm Net::Telnet                      # patch Net::Telnet class  
#     opts['ACL'] = IPAccess::Set.new                    # create custom access set and add it to options
#     opts['ACL'].output.blacklist 'randomseed.pl'  # blacklist host
#     
#     t = Net::Telnet.new(opts)             # try to connect to remote host
# 
# ==== Private access set, class patched, direct blacklisting
#                                        
#     require 'ipaccess/net/telnet'         # load Net::Telnet version and IPAccess.arm method
#     
#     opts = {}
#     opts["Host"]  = 'randomseed.pl'
#     opts["Port"]  = '80'
#     
#     IPAccess.arm Net::Telnet              # patch Net::Telnet class  
#     
#     t = Net::Telnet.new(opts, :private)   # try to connect to remote host
#     t.blacklist 'randomseed.pl'           # blacklist host

class IPAccess::Net::Telnet
  
  #:include:ghost_doc_p_whitelist_e.rb
  def whitelist!; end

  #:include:ghost_doc_p_whitelist.rb
  def whitelist; end

  #:include:ghost_doc_p_blacklist_e.rb
  def blacklist!; end

  #:include:ghost_doc_p_blacklist.rb
  def blacklist; end

  #:include:ghost_doc_p_unwhitelist.rb
  def unwhitelist; end

  #:include:ghost_doc_p_unwhitelist_e.rb
  def unwhitelist!; end

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
  #     require 'ipaccess/net/telnet'             # load Net::Telnet variant
  #     
  #     opts = {}
  #     opts["Host"] = 'randomseed.pl'
  #     telnet = IPAccess::Net::Telnet.new(opts)  # create connected Telnet object
  # 
  #     telnet.acl = :global                      # use global access set
  #     telnet.acl = :private                     # create and use individual access set
  #     telnet.acl = IPAccess::Set.new                 # use external (shared) access set

  attr_writer :acl
  

  # This member keeps the information about currently
  # used access set. You may use it to do low-level
  # operations on IPAccess object associated
  # with instance. You cannot however call any
  # of global access set operations – to do that
  # use IPAccess::Set.Global contant referencing to
  # global ACL.

  attr_reader :acl
  
  # The socket the Telnet object is using, which is kind of TCPSocket and
  # responds to all methods of IPAccess::TCPSocket.
  # Note that this object becomes a delegate of the Telnet object,
  # so normally you invoke its methods directly on the Telnet object.
  
  attr_reader :sock
  
  # :call-seq:
  #   new(opts) <tt>{|mesg| …}</tt><br />
  #   new(opts, acl)<tt>{|mesg| …}</tt> 
  # 
  # Creates a new object and attempts to connect
  # to the host (unless the Proxy option is provided).
  # If a block is provided, it is yielded as status messages
  # on the attempt to connect to the server.
  # It optionally sets an access set given as the
  # last parameter or as +ACL+ member of +opts+.
  # The access set given as an argument has precedence
  # over access set given in options. If ACL parameter
  # is not given it defaults to ACL to <tt>IPAccess::Set.Global</tt>.
  
  def initialize
    # Real code hidden.
  end
  
  # This method allows you to re-check access on demad.
  # It uses internal socket's address and access set assigned
  # to an object.
  
  def acl_recheck
    # Real code hidden.
  end
  
end
