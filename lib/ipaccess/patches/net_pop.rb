# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby's Net::POP3 class in order to add
# IP access control to it. It is also used
# to create variant of Net::POP3 class
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
require 'net/pop'
require 'ipaccess/ip_access_errors'
require 'ipaccess/patches/generic'
require 'ipaccess/patches/sockets'

# :stopdoc:

module IPAccess::Patches::Net
  
  ###################################################################
  # Net::POP3 class with IP access control.
  # It uses output access lists.
  
  module POP3
    
    include IPAccess::Patches::ACL
    
    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
        
        # CLASS METHODS
        unless (base.name.nil? && base.class.name == "Class")
          (class << self; self; end).class_eval do
            
            # overwrite POP3.start()
            define_method :__ipacall__start do |block, address, *args|
              late_acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
              late_on_deny = nil
              args.delete_if { |x| late_on_deny = x if (x.is_a?(Symbol) && x == :opened_on_deny) }
              port, account, password, isapop = *args
              isapop = false if isapop.nil?
              obj = new(address, port, isapop, late_acl, late_on_deny)
              obj.start(account, password, &block)
            end
            
            # block passing wrapper for Ruby 1.8
            def start(address, *args, &block)
              __ipacall__start(block, address, *args)
            end
            
            # overwrite POP3.delete_all()
            define_method :__ipacall__delete_all do |block, address, *args|
              start(address, *args) { |pop|
                pop.delete_all(&block)
              }
            end
            
            # block passing wrapper for Ruby 1.8
            def delete_all(address, *args, &block)
              __ipacall__delete_all(block, address, *args)
            end
            
            # overwrite POP3.auth_only()
            define_method :auth_only do |address, *args|
              port, account, password, isapop, late_acl = *args
              new(address, port, isapop, late_acl).auth_only account, password
            end        
            
            # overwrite POP3.foreach()
            define_method :__ipacall__foreach do |block, address, *args|
              start(address, *args) { |pop|
                pop.each_mail(&block)
              }
            end
            
            # block passing wrapper for Ruby 1.8
            def foreach(address, *args, &block)
              __ipacall__foreach(block, address, *args)
            end
            
      	  end
      	
    	  end # class methods
        
        orig_initialize       = self.instance_method :initialize
        orig_do_start         = self.instance_method :do_start
        orig_on_connect       = self.instance_method :on_connect
        
        # initialize on steroids.
        define_method  :initialize do |addr, *args|
          @close_on_deny = true
          args.delete_if { |x| @close_on_deny = false if (x.is_a?(Symbol) && x == :opened_on_deny) }
          self.acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
          obj = orig_initialize.bind(self).call(addr, *args)
          self.acl_recheck
          return obj
        end
        
        # start on steroids.
        define_method :do_start do |account, password|
          prev_addr = @address
          ipaddr = TCPSocket.getaddress(@address)
          real_acl.check_out_ipstring ipaddr
          @address = ipaddr
          ret = orig_do_start.bind(self).call(account, password)
          @address = prev_addr
          self.acl_recheck
          return ret
        end
        
        # on_connect on steroids.
        define_method :on_connect do
          acl_recheck
          orig_on_connect.bind(self).call
        end
        
        # This method returns default access list indicator
        # used by protected object; in this case it's +:output+.
        define_method :default_list do
          :output
        end
                
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          try_arm_and_check_socket @socket
          nil
        end
        
        # this hook terminates connection
        define_method :terminate do
          self.finish if started?
          nil
        end
                
      end # base.class_eval

    end # self.included
    
  end # module POP3
  
end # module IPAccess::Patches

# :startdoc:

