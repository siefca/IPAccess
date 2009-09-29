# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby's Net::Telnet class in order to add
# IP access control to it. It is also used
# to create variant of Net::Telnet class
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
require 'net/telnet'
require 'ipaccess/ip_access_errors'
require 'ipaccess/patches/generic'
require 'ipaccess/patches/sockets'

# :stopdoc:

module IPAccess::Patches::Net
  
  ###################################################################
  # Net::Telnet class with IP access control.
  # It uses output access lists.
  
  module Telnet
    
    include IPAccess::Patches::ACL
    
    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
        
        orig_initialize     = self.instance_method :initialize
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          begin
            self.acl.check_out_socket @sock
          rescue IPAccessDenied
            self.close
            raise
          end
          if (@sock.is_a?(TCPSocket) || (Object.const_defined?(:SOCKSSocket) && @sock.is_a?(SOCKSSocket)))
            IPAccess.arm(@sock, acl) unless @sock.respond_to?(:acl)
            @sock.acl = self.acl if @sock.acl != self.acl # share socket's access set with Net::Telnet object
          end
          nil
        end
        
        # initialize on steroids
        define_method  :__ipacall__initialize do |block, *args|
          options = args.first
          options["ACL"] = args.pop if (IPAccess.valid_acl?(args.last) && options.is_a?(Hash))
          options["Host"] = "localhost" unless options.has_key?("Host")
          self.acl = IPAccess.valid_acl?(options["ACL"]) ? options["ACL"] : :global
          options["Host"] = TCPSocket.getaddress(options["Host"])
          self.acl.check_out_ipstring options["Host"]
          args[0] = options
          ret = orig_initialize.bind(self).call(*args, &block)
          self.acl_recheck
          return ret
        end
        
        # block passing wrapper for Ruby 1.8
        def initialize(*args, &block)
          __ipacall__initialize(block, *args)
        end
        
        # SINGLETON HOOKS
        def __ipa_singleton_hook(acl=nil)
          self.acl = acl.nil? ? @options["ACL"] : acl
          self.acl_recheck
        end # singleton hooks
        private :__ipa_singleton_hook
        
      end # base.class_eval

    end # self.included
    
  end # module Telnet
  
end # module IPAccess::Patches

# :startdoc:

