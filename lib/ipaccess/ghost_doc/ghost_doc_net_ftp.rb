# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009-2014 by Paweł Wilk
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
# input access lists. It and acts the same way as Net::FTP[http://www.ruby-doc.org/stdlib/libdoc/net/ftp/rdoc/classes/Net/FTP.html]
# class but provides special member called +acl+ and a few new
# instance methods for controlling IP access.
# 
#:include:ghost_doc_patched_usage.rb
# 
# This documentation doesn't cover description of all
# class and instance methods of the original
# Net::FTP[http://www.ruby-doc.org/stdlib/libdoc/net/ftp/rdoc/classes/Net/FTP.html]
# class, just the patched variants that make use of IP access control.
# 
# === Examples
# 
# ==== Using IPAccess::Net::FTP variant instead of Net::FTP[http://www.ruby-doc.org/stdlib/libdoc/net/ftp/rdoc/classes/Net/FTP.html], private access set
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
#     ftp.blacklist 'ftp.pld-linux.org'
#     
#     # try to get listing
#     files = ftp.list('n*')
#     ftp.close
#     
# ==== Using patched Net::FTP[http://www.ruby-doc.org/stdlib/libdoc/net/ftp/rdoc/classes/Net/FTP.html] instance
#     
#     require 'ipaccess/net/ftp'
#     
#     # create shared access set
#     acl = IPAccess::Set.new
#     acl.output.blacklist 'ftp.pld-linux.org'
#     
#     # create an object and connect
#     ftp = Net::FTP.new('ftp.pld-linux.org')
#     ftp.passive = true
#     ftp.login
#     
#     # arm the object and associate shared access set with it
#     IPAccess.arm ftp, acl
# 
#     # perform some operations (an exception should be raised earlier)
#     files = ftp.chdir('/')
#     files = ftp.list('n*')
#     ftp.close
#     
# ==== Using patched Net::FTP[http://www.ruby-doc.org/stdlib/libdoc/net/ftp/rdoc/classes/Net/FTP.html] class
#     
#     acl = IPAccess::Set.new
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
  
  # This method works like whitelist! but
  # allows to set reason.
  def whitelist_reasonable!(reason, *addresses); end

  # This method works like whitelist but
  # allows to set reason.
  def whitelist_reasonable(reason, *addresses); end

  # This method works like blacklist! but
  # allows to set reason.
  def blacklist_reasonable!(reason, *addresses); end

  # This method works like blacklist but
  # allows to set reason.
  def blacklist_reasonable(reason, *addresses); end
  
  #:include:ghost_doc_acl.rb
  #  
  # === Example
  # 
  #     require 'ipaccess/net/ftp'             # load Net::FTP variant
  #     
  #     ftp = IPAccess::Net::FTP.new('host')   # create connected Telnet object
  # 
  #     ftp.acl = :global                      # use global access set
  #     ftp.acl = :private                     # create and use individual access set
  #     ftp.acl = IPAccess::Set.new            # use external (shared) access set

  attr_accessor :acl
  
  # :call-seq:
  #   new()<br />
  #   new(acl)<br />
  #   new(host, acl)<br />
  #   new(host, user, passwd, acl)<br />
  #   new(host, user, passwd, account, acl)
  # 
  # Creates and returns a new FTP object. If a +host+ is given,
  # a connection is made. Additionally, if the +user+ is given,
  # the given +user+ name, +password+, and (optionally) +account+
  # are used to log in.
  #
  # It optionally sets an access set given as the
  # last parameter. If +acl+ parameter
  # is not given it defaults to <tt>IPAccess::Set.Global</tt>.
  
  def initialize
    # Real code hidden.
  end
  
  # :call-seq:
  #   open(host, acl) <tt>{|ftp| …}</tt>|<br />
  #   open(host, user, passwd, acl) <tt>{|ftp| …}</tt>|<br />
  #   open(host, user, passwd, account, acl) <tt>{|ftp| …}</tt>|
  # 
  # A synonym for new, but with a mandatory host parameter.
  # If a block is given, it is passed the FTP object,
  # which will be closed when the block finishes,
  # or when an exception is raised.
  #
  # It optionally sets an access set given as the
  # last parameter. If the parameter
  # is not given it defaults to <tt>IPAccess::Set.Global</tt>.
  
  def self.open
    # Real code hidden.
  end
  
  # This method allows you to re-check access on demad.
  # It uses internal socket's address and access set assigned
  # to an object. It will close your communication session
  # before throwing an exception in case of denied access
  # – you can prevent it by setting the flag +opened_on_deny+
  # to +true+. The flag can be set while initializing object
  # (through argument +:opened_on_deny+) or by setting the
  # attribute.
  
  def acl_recheck
    # Real code hidden.
  end
  
end
