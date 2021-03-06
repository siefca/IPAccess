# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009-2014 by Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:LGPL.html] or Ruby License.
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
# Net::HTTP[http://www.ruby-doc.org/stdlib/libdoc/net/http/rdoc/classes/Net/HTTP.html]
# class with IP access control. It uses *output* access lists
# and acts the same way as Net::HTTP[http://www.ruby-doc.org/stdlib/libdoc/net/http/rdoc/classes/Net/HTTP.html] class but
# provides special member called +acl+ and a few new
# instance methods for controlling IP access.
# 
# {include:file:lib/ipaccess/ghost_doc/ghost_doc_patched_usage.rdoc}
# 
# This documentation doesn't cover description of all
# class and instance methods of the original
# Net::HTTP[http://www.ruby-doc.org/stdlib/libdoc/net/http/rdoc/classes/Net/HTTP.html]
# class, just the patched variants that make use of IP access control.
# 
# === Examples
#
# ==== Simple method, global access set
#
#     require 'ipaccess/net/http'
#     
#     # blacklist randomseed.pl in global access set
#     IPAccess::Set::Global.output.blacklist 'randomseed.pl'
#     
#     # call get_print
#     IPAccess::Net::HTTP.get_print 'randomseed.pl', '/index.html'
# 
# ==== Simple method, shared access set
#
#     require 'ipaccess/net/http'
#     
#     # create access set
#     acl = IPAccess::Set.new
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
#     acl = IPAccess::Set.new
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
#     htt.blacklist 'randomseed.pl'                         # blacklist randomseed.pl and re-check
#     res = htt.start { |http|                              # start HTTP session
#       http.request(req)                                   # and send the request
#     }
# 
#
# ==== Generic method, shared access set, single object patched
#
#     require 'ipaccess/net/http'
#     
#     # create custom access set with one blacklisted IP
#     acl = IPAccess::Set.new
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
#     acl = IPAccess::Set.new
#     acl.output.blacklist 'randomseed.pl'
#     
#     # patch whole Net::HTTP class
#     IPAccess.arm Net::HTTP
#     
#     # call get_print with passed access set
#     Net::HTTP.get_print 'randomseed.pl', '/index.html', acl
#

class IPAccess::Net::HTTP

  # {include:IPAccess::Socket#whitelist!}
  # @overload whitelist!(*addresses)
  # @overload whitelist!(list, *addresses)
  def whitelist!(*addresses); end

  # {include:IPAccess::Socket#whitelist}
  # @overload whitelist(*addresses)
  # @overload whitelist(list, *addresses)
  def whitelist(*addresses); end

  # {include:IPAccess::Socket#blacklist!}
  # @overload blacklist!(*addresses)
  # @overload blacklist!(list, *addresses)
  def blacklist!(*addresses); end

  # {include:IPAccess::Socket#blacklist}
  # @overload blacklist(*addresses)
  # @overload blacklist(list, *addresses)
  def blacklist(*addresses); end

  # {include:IPAccess::Socket#unwhitelist!}
  # @overload unwhitelist!(*addresses)
  # @overload unwhitelist!(list, *addresses)
  def unwhitelist!(*addresses); end
  
  # {include:IPAccess::Socket#unwhitelist}
  # @overload unwhitelist(*addresses)
  # @overload unwhitelist(list, *addresses)
  def unwhitelist(*addresses); end

  #{include:IPAccess::Socket#unblacklist!}
  # @overload unblacklist!(*addresses)
  # @overload unblacklist!(list, *addresses)
  def unblacklist!(*addresses); end

  #{include:IPAccess::Socket#unblacklist}
  # @overload unblacklist(*addresses)
  # @overload unblacklist(list, *addresses)
  def unblacklist(*addresses); end

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
    
  #{include:file:lib/ipaccess/ghost_doc/ghost_doc_acl.rdoc}
  #  
  # === Example
  # 
  #     require 'ipaccess/net/http'                         # load Net::HTTP variant
  #     
  #     http = IPAccess::Net::HTTP.new('randomseed.pl', 80) # create HTTP object
  # 
  #     http.acl = :global                      # use global access set
  #     http.acl = :private                     # create and use individual access set
  #     http.acl = IPAccess::Set.new                 # use external (shared) access set

  attr_accessor :acl

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

  # Creates a new object for the specified address.
  # This method does not open the TCP connection.
  # It optionally sets an access set given as the
  # last parameter. If parameter is not given it
  # sets ACL to IPAccess::Set.Global.
  # 
  # Flags are symbols that control behavior of IPAccess:
  # 
  #   * +:opened_on_deny+ causes blocking method to leave a socket open when access is denied and a socket was re-checked
  #   * +:check_only_proxy+ causes access checks to be applied only to a proxy server address if a proxy is in use
  #   * +:check_only_real+ causes access check to be applied only to a destination address (and not to proxy server) if a proxy is in use
  # 
  # @overload new(address)
  # @overload new(address, acl)
  # @overload new(address, port, acl)
  # @overload new(address, acl, *flags)
  # @overload new(address, port, acl, *flags)

  def initialize(address)
    # Real code hidden.
  end

  # :call-seq:
  #   start(address, acl) <tt>{|http| …}</tt><br />
  #   start(address, port, acl) <tt>{|http| …}</tt><br />
  #   start(address, port, p_addr, acl) <tt>{|http| …}</tt><br />
  #   start(address, port , p_addr, p_port, acl) <tt>{|http| …}</tt><br />
  #   start(address, port, p_addr, p_port, p_user, p_pass, acl) <tt>{|http| …}</tt><br />
  #   start(address, port = nil, p_addr = nil, p_port = nil, p_user = nil, p_pass = nil) <tt>{|http| …}</tt>
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
  # it sets ACL to IPAccess::Set.Global.
  
  def self.start
    # Real code hidden.
  end

  # :call-seq:
  #   get_response(uri_or_host, path, port, acl) <tt>{|http| …}</tt>|<br />
  #   get_response(uri_or_host, path, acl) <tt>{|http| …}</tt><br />
  #   get_response(uri_or_host, acl) <tt>{|http| …}</tt><br />
  #   get_response(uri_or_host, path = nil, port = nil) <tt>{|http| …}</tt>
  #   
  # Sends a GET request to the target and return the response as a Net::HTTPResponse object.
  # The target can either be specified as (uri), or as
  # (host, path, port = 80).
  # It optionally sets an access set given as the
  # last parameter. If parameter is not given it
  # sets ACL to IPAccess::Set.Global.
  
  def self.get_response
    # Real code hidden.
  end
  
end
