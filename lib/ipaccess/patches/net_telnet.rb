# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009-2014 by Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL.html] or {Ruby License}[link:docs/COPYING.html].
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
        
        # initialize on steroids.
        define_method  :__ipacall__initialize do |block, *args|
          @opened_on_deny = !!args.reject! { |x| x.is_a?(Symbol) && x == :opened_on_deny }
          args.pop if args.last.nil?
          options = args.first
          options["ACL"] = args.pop if (IPAccess.valid_acl?(args.last) && options.is_a?(Hash))
          options["Host"] = "localhost" unless options.has_key?("Host")
          self.acl = IPAccess.valid_acl?(options["ACL"]) ? options["ACL"] : :global
          options["Host"] = ::TCPSocket.getaddress(options["Host"])
          self.acl.output.check_ipstring(options["Host"], :none)
          args[0] = options
          ret = orig_initialize.bind(self).call(*args, &block)
          self.acl_recheck
          return ret
        end
        
        # This method returns default access list indicator
        # used by protected object; in this case it's +:output+.
        define_method :default_list do
          :output
        end
        
        # this hook terminates connection
        define_method :terminate do
          self.close unless self.closed?
        end
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          try_arm_and_check_socket @sock
          nil
        end
                
        # block passing wrapper for Ruby 1.8
        def initialize(*args, &block)
          __ipacall__initialize(block, *args)
        end
                
      end # base.class_eval

    end # self.included
    
  end # module Telnet
  
end # module IPAccess::Patches

# :startdoc:

