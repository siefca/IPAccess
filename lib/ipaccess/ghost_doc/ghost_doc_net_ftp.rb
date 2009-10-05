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
# Net::FTP[http://www.ruby-doc.org/stdlib/libdoc/net/ftp/rdoc/classes/Net/FTP.html]
# class with IP access control. It uses output and occasionally
# input access lists. It and acts the same way as Net::FTP
# class but provides special member called +acl+ for
# controlling IP access. Access checks are lazy
# which means they are performed when real connection
# is going to happend. Instances of this class will also
# internally use patched versions of Ruby's network
# socket objects to avoid access leaks.
# 
# You can pass access set in various ways: while
# creating Telnet object or while starting Telnet session.
# You can also rely on global access set.
#
# === Usage
# 
# There are 3 ways to enable access control:
#
# * patching Net::Telnet[http://www.ruby-doc.org/stdlib/libdoc/net/ftp/rdoc/classes/Net/FTP.html] class (see IPAccess.arm) – use it in code you cannot easily modify
# * patching single instance (see IPAccess.arm) – use it occasionally
# * using IPAccess::Net::Telnet class – use it in your own code
# 
# There are also 3 ways to manage access rules:
# 
# * using direct methods like blacklist and whitelist – preferred, ensures that access check is done after change
# * using acl member – you may control only private and shared access sets that way and have to ensure that re-check is done after change
# * using IPAccess::Global constant – use it when object is associated with global access set
# 
# The +acl+ member and IPAccess::Global are IPAccess instances.
# Direct methods are documented below – they are easy to use
# but their appliance is limited to existing objects (since they
# are instance methods). That sometimes may be not what you need,
# for example in case of quick setups when connection is made in
# the very moment new object is created or when single object is patched
# (armed) in connected state. Remeber to call acl_recheck
# immediately after operation to avoid leaks
# when you're using +acl+ member or IPAccess::Global
# to manage access rules.
# 
# This documentation doesn't cover description of all
# class and instance methods of the original
# Net::FTP[http://www.ruby-doc.org/stdlib/libdoc/net/ftp/rdoc/classes/Net/FTP.html]
# class, just the patched variants that make use of IP access control.
# 
# === Examples
# 
# ==== Using IPAccess::Net::FTP variant instead of Net::FTP, private access set
#     
#     require 'ipaccess/net/ftp'
#     
#     # set up FTP object with private ACL assigned
#     ftp = IPAccess::Net::FTP.new('ftp.pld-linux.org', :private)
#     ftp.passive = true
#     
#     # login to remote host
#     ftp.login
#     files = ftp.chdir('/')
#     
#     # blacklist the host (a bit late but we'll try)
#     ftp.acl.output.blacklist 'ftp.pld-linux.org'
#     
#     # this command opens socket so there is no need to call ftp.acl_recheck
#     files = ftp.list('n*')
#     ftp.close
#     
# ==== Using patched Net::FTP object
#     
#     require 'ipaccess/net/ftp'
#     
#     acl = IPAccess.new
#     acl.output.blacklist 'ftp.pld-linux.org'
#     ftp = Net::FTP.new('ftp.pld-linux.org')
#     ftp.passive = true
#     ftp.login
#     IPAccess.arm ftp, acl
#     files = ftp.chdir('/')
#     files = ftp.list('n*')
#     ftp.close
#     
#     # Using patched Net::FTP class
#     
#     acl = IPAccess.new
#     IPAccess.arm Net::FTP
#     ftp = Net::FTP.new('ftp.pld-linux.org')
#     ftp.acl = acl
#     ftp.passive = true
#     ftp.login
#     files = ftp.chdir('/')
#     acl.output.blacklist 'ftp.pld-linux.org'
#     files = ftp.list('n*')
#     ftp.close

class IPAccess::Net::FTP
  
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
  #     require 'ipaccess/net/ftp'                # load Net::FTP variant
  #     
  #     telnet = IPAccess::Net::FTP.new('host')   # create connected Telnet object
  # 
  #     telnet.acl = :global                      # use global access set
  #     telnet.acl = :private                     # create and use individual access set
  #     telnet.acl = IPAccess.new                 # use external (shared) access set

  attr_writer :acl
  
  # This member keeps the information about currently
  # used access set. You may use it to do low-level
  # operations on IPAccess object associated
  # with instance. You cannot however call any
  # of global access set operations – to do that
  # use IPAccess::Global contant referencing to
  # global ACL.
  
  attr_reader :acl
  
  # :call-seq:
  #   new(opts) <tt>{|mesg| …}</tt><br />
  #   new(opts, acl)<tt>{|mesg| …}</tt> 
  # 
  # Creates a new object and attempts to connect
  #
  # It optionally sets an access set given as the
  # last parameter or as +ACL+ member of +opts+.
  # The access set given as an argument has precedence
  # over access set given in options. If ACL parameter
  # is not given it defaults to ACL to IPAccess::Global.
  
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
