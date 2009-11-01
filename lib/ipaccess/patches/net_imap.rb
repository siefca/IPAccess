# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby's Net::IMAP class in order to add
# IP access control to it. It is also used
# to create variant of Net::IMAP class
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
# 

require 'socket'
require 'net/imap'
require 'ipaccess/ip_access_errors'
require 'ipaccess/patches/generic'
require 'ipaccess/patches/sockets'

# :stopdoc:

module IPAccess::Patches::Net
  
  ###################################################################
  # Net::IMAP class with IP access control.
  # It uses output access lists.
  
  module IMAP
    
    include IPAccess::Patches::ACL
    
    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
        
        orig_initialize       = self.instance_method :initialize
        orig_authenticate     = self.instance_method :authenticate
        orig_start_tls_session= self.instance_method :start_tls_session if self.method_defined?(:start_tls_session)
        
        # initialize on steroids.
        define_method  :__ipacall__initialize do |block, host, *args|
          @opened_on_deny = false
          args.delete_if { |x| @opened_on_deny = true if (x.is_a?(Symbol) && x == :opened_on_deny) }
          args.pop if args.last.nil?
          self.acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
          ipaddr = ::TCPSocket.getaddress(host)
          real_acl.check_out_ipstring(ipaddr, :none)
          obj = orig_initialize.bind(self).call(ipaddr, *args, &block)
          @host = host
          self.acl_recheck
          return obj
        end
        
        # authenticate on steroids.
        define_method :authenticate do |auth_type, *args|
          self.acl_recheck
          orig_authenticate.bind(self).call(auth_type, *args)
        end
        
        # block passing wrapper for Ruby 1.8
        def initialize(host, *args, &block)
          __ipacall__initialize(block, host, *args)
        end
        
        # start_tls_session on steroids.
        if self.method_defined?(:start_tls_session)
          define_method :start_tls_session do |params|
            ret = orig_start_tls_session.bind(self).call(params)
            self.acl_recheck
            return ret
          end
        end
        
        # This method returns default access list indicator
        # used by protected object; in this case it's +:output+.
        define_method :default_list do
          :output
        end
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
         try_arm_and_check_socket @sock
         nil
        end
        
        # this hook terminates connection
        define_method :terminate do
          self.disconnect unless disconnected?
        end
      
      end # base.class_eval

    end # self.included
    
  end # module IMAP
  
end # module IPAccess::Patches

# :startdoc:

