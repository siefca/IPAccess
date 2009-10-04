# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby's Net::HTTP class in order to add
# IP access control to it. It is also used
# to create variant of Net::HTTP class
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
require 'net/http'
require 'ipaccess/ip_access_errors'
require 'ipaccess/patches/generic'
require 'ipaccess/patches/sockets'

# :stopdoc:

module IPAccess::Patches::Net
  
  ###################################################################
  # Net::HTTP class with IP access control.
  # It uses output access lists.
  
  module HTTP
    
    include IPAccess::Patches::ACL
    
    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
        
        # CLASS METHODS
        unless (base.name.nil? && base.class.name == "Class")
          (class << self; self; end).class_eval do
            
            alias :__ipac__orig_new :new
            
            # overload HTTP.new() since it's not usual.
        	  define_method :new do |address, *args|
        	    late_acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
              obj = __ipac__orig_new(address, *args)
              obj.acl = late_acl unless obj.acl == late_acl
              return obj
            end
            
            # overwrite HTTP.start()
            define_method :__ipacall__start do |block, address, *args|
              acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
              port, p_addr, p_port, p_user, p_pass = *args
              new(address, port, p_addr, p_port, p_user, p_pass, acl).start(&block)
            end
            
            # block passing wrapper for Ruby 1.8
            def start(*args, &block)
              __ipacall__start(block, *args)
            end

            # overwrite HTTP.get_response()
        	  define_method :__ipacall__get_response do |block, uri_or_host, *args|
        	    late_acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
        	    path, port = *args
        	    if path
                host = uri_or_host
                new(host, (port || Net::HTTP.default_port), late_acl).start { |http|
                  return http.request_get(path, &block)
                }
              else
                uri = uri_or_host
                new(uri.host, uri.port, late_acl).start { |http|
                  return http.request_get(uri.request_uri, &block)
                }
              end
            end
            
            # block passing wrapper for Ruby 1.8
            def get_response(*args, &block)
              __ipacall__get_response(block, *args)
            end
            
      	  end
      	
    	  end # class methods
        
        orig_initialize       = self.instance_method :initialize
        orig_conn_address     = self.instance_method :conn_address
        orig_on_connect       = self.instance_method :on_connect
        
        # initialize on steroids.
        define_method  :__ipacall__initialize do |block, *args|
          self.acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
          orig_initialize.bind(self).call(*args, &block)
        end
        
        # block passing wrapper for Ruby 1.8
        def initialize(*args, &block)
          __ipacall__initialize(block, *args)
        end
                
        # on_connect on steroids.
        define_method :on_connect do
          acl_recheck # check address form socket to be sure
          orig_on_connect.bind(self).call
        end
        private :on_connect
        
        # conn_address on steroids.
        define_method :conn_address do
          addr = orig_conn_address.bind(self).call
          ipaddr = TCPSocket.getaddress(addr)
          real_acl.check_out_ipstring ipaddr
          return ipaddr
        end
        private :conn_address
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          begin
            try_arm_and_check_socket @socket
          rescue IPAccessDenied
            begin
              self.finish
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
    
  end # module HTTP
  
end # module IPAccess::Patches

# :startdoc:

