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
# Net::SMTP[http://www.ruby-doc.org/stdlib/libdoc/net/smtp/rdoc/classes/Net/SMTP.html]
# class with IP access control. It uses +output+
# access lists. It and acts the same way as Net::SMTP[http://www.ruby-doc.org/stdlib/libdoc/net/smtp/rdoc/classes/Net/SMTP.html]
# class but provides special member called +acl+ and a few new
# instance methods for controlling IP access.
# 
#:include:ghost_doc_patched_usage.rb
#
# This documentation doesn't cover description of all
# class and instance methods of the original
# Net::SMTP[http://www.ruby-doc.org/stdlib/libdoc/net/smtp/rdoc/classes/Net/SMTP.html]
# class, just the patched variants that make use of IP access control.
# 
# === Examples
# 
# ==== Using IPAccess::Net::SMTP variant instead of Net::SMTP[http://www.ruby-doc.org/stdlib/libdoc/net/smtp/rdoc/classes/Net/SMTP.html], global access set
#     
#     require 'ipaccess/net/smtp'
# 
#     IPAccess::Set.Global.output.blacklist 'randomseed.pl'
#     
#     IPAccess::Net::SMTP.start('randomseed.pl', 25) do |smtp|
#       ;
#     end
# 
# ==== Patching single object, global access set, direct blacklisting
# 
#     require 'ipaccess/net/smtp'
#     
#     p = Net::SMTP.new 'randomseed.pl'
#     IPAccess.arm p
#     p.blacklist! 'randomseed.pl'
#     p.start
   
class IPAccess::Net::SMTP
  
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
  #     require 'ipaccess/net/smtp'             # load Net::SMTP variant
  #     
  #     smtp = IPAccess::Net::SMTP.new('host')  # create SMTP object
  # 
  #     smtp.acl = :global                      # use global access set
  #     smtp.acl = :private                     # create and use individual access set
  #     smtp.acl = IPAccess::Set.new                 # use external (shared) access set

  attr_writer :acl
  
  # This member keeps the information about currently
  # used access set. You may use it to do low-level
  # operations on IPAccess object associated
  # with instance. You cannot however call any
  # of global access set operations – to do that
  # use IPAccess::Set.Global contant referencing to
  # global ACL.
  
  attr_reader :acl
  
  # :call-seq:
  #   new(address)<br />
  #   new(address, acl)<br />
  #   new(address, port, acl)
  # 
  # Creates a new object. Argument +address+ is the hostname
  # or IP address of your SMTP server. Argument +port+ is
  # the port to connect to; it defaults to port 25.
  #
  # This method does not open the TCP connection.
  # You can use SMTP.start instead of SMTP.new
  # if you want to do everything at once.
  # Otherwise, follow SMTP.new with SMTP#start.
  # 
  # This method optionally sets an access set given as the
  # last parameter. If +acl+ parameter
  # is not given it defaults to <tt>IPAccess::Set.Global</tt>.
  
  def initialize
    # Real code hidden.
  end
  
  # :call-seq:
  #   start(address) <tt>{|smtp| …}</tt><br />
  #   start(address, acl) <tt>{|smtp| …}</tt><br />
  #   start(address, port, acl) <tt>{|smtp| …}</tt><br />
  #   start(address, port, helo, acl) <tt>{|smtp| …}</tt><br />
  #   start(address, port, helo, user, secret, acl) <tt>{|smtp| …}</tt><br />
  #   start(address, port, helo, user, secret, authtype, acl) <tt>{|smtp| …}</tt>
  #
  # Creates a new object and connects to the server. If +helo+
  # is missing or +nil+ the +localhost.localdomain+ string will
  # be used. This method is equivalent to:
  #
  #   smtp = IPAccess::Net::SMTP.new(address, port)
  #   smtp.start(helo_domain, account, password, authtype)
  # 
  # This method optionally sets an access set given as the
  # last parameter. If +acl+ parameter
  # is not given it defaults to <tt>IPAccess::Set.Global</tt>.
  
  def self.start
    # Real code hidden.
  end
    
  # This method allows you to re-check access on demad.
  # It uses internal socket's address and access set assigned
  # to an object.
  
  def acl_recheck
    # Real code hidden.
  end
  
end
