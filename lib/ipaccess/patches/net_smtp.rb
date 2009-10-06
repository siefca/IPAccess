# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby's Net::SMTP class in order to add
# IP access control to it. It is also used
# to create variant of Net::SMTP class
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
require 'net/smtp'
require 'ipaccess/ip_access_errors'
require 'ipaccess/patches/generic'
require 'ipaccess/patches/sockets'

# :stopdoc:

module IPAccess::Patches::Net
  
  ###################################################################
  # Net::SMTP class with IP access control.
  # It uses output access lists.
  
  module SMTP
    
    include IPAccess::Patches::ACL
    
    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
        
        # CLASS METHODS
        unless (base.name.nil? && base.class.name == "Class")
          (class << self; self; end).class_eval do
            
            # overwrite SMTP.start()
            define_method :__ipacall__start do |block, address, *args|
              late_acl = IPAccess.valid_acl?(args.last) ? args.smtp : :global
              port, helo, user, secret, authtype = *args
              obj = new(address, port, late_acl)
              obj.start(helo, user, secret, authtype, &block)
            end
            
            # block passing wrapper for Ruby 1.8
            def start(address, *args, &block)
              __ipacall__start(block, address, *args)
            end
                        
      	  end
      	
    	  end # class methods
        
        orig_initialize       = self.instance_method :initialize
        orig_do_start         = self.instance_method :do_start
        
        # initialize on steroids.
        define_method  :initialize do |addr, *args|
          self.acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
          obj = orig_initialize.bind(self).call(addr, *args)
          self.acl_recheck
          return obj
        end
      
        # start on steroids.
        define_method :do_start do |helo_domain, user, secret, authtype|
          prev_addr = @address
          ipaddr = TCPSocket.getaddress(@address)
          real_acl.check_out_ipstring ipaddr
          @address = ipaddr
          ret = orig_do_start.bind(self).call(helo_domain, user, secret, authtype)
          @address = prev_addr
          self.acl_recheck
          return ret
        end
        private :do_start
        
        # This method returns default access list indicator
        # used by protected object; in this case it's +:output+.
        define_method :default_list do
          :output
        end
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          begin
            try_arm_and_check_socket @socket
          rescue IPAccessDenied
            begin
              self.finish if started?
            rescue IOError
            end
            raise
          end
          nil
        end
        
        # SINGLETON HOOKS
        def __ipa_singleton_hook(acl=nil)
          self.acl = acl
          self.acl_recheck
        end # singleton hooks
        private :__ipa_singleton_hook
        
      end # base.class_eval

    end # self.included
    
  end # module SMTP
  
end # module IPAccess::Patches

# :startdoc:

