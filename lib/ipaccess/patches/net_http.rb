# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby's Net::HTTP classes in order to add
# IP access control to  it. It is also used
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
            alias_method :__ipac_new, :new
        	  private :__ipac_new
        	
        	  # override HTTP.new() since it's not usual.
        	  define_method :new do |*args|
        	    late_acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
        	    obj = __ipac_new(*args)
        	    obj.acl = late_acl if obj.respond_to?(:acl)
        	    return obj
      	    end
          
            # overwrite HTTP.start()
            def start(address, *args, &block) # :yield: +http+
              acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
              port, p_addr, p_port, p_user, p_pass = *args
              new(address, port, p_addr, p_port, p_user, p_pass, acl).start(&block)
            end

            # overwrite HTTP.get_response()
        	  def get_response(uri_or_host, *args, &block)
        	    acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
        	    path, port = *args
        	    if path
                host = uri_or_host
                new(host, (port || Net::HTTP.default_port), acl).start { |http|
                  return http.request_get(path, &block)
                }
              else
                uri = uri_or_host
                new(uri.host, uri.port, acl).start { |http|
                  return http.request_get(uri.request_uri, &block)
                }
              end
            end
            
      	  end
      	
    	  end # class methods
        
        orig_conn_address     = self.instance_method :conn_address
        orig_on_connect       = self.instance_method :on_connect
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          acl = @acl.nil? ? IPAccess::Global : @acl
          begin
            sock = @socket
            sock = sock.io if (!sock.nil? && sock.respond_to?(:io) && sock.io.respond_to?(:getpeername))
            real_acl.check_out_socket sock
          rescue IPAccessDenied
            begin
              self.finish
            rescue IOError
            end
            raise
          end
          if sock.is_a?(TCPSocket)
            unless sock.respond_to?(:acl)
              (class <<sock; self; end).__send__(:include, IPAccess::Patches::TCPSocket)
            end
            sock.acl = acl if sock.acl != acl # share socket's access set with Net::Telnet object
          end
          nil
        end
        
        # on_connect on steroids.
        define_method :on_connect do
          acl_recheck # check address form socket to be sure
        end
        
        # conn_address on steroids.
        define_method :conn_address do
          acl = @acl.nil? ? IPAccess::Global : @acl
          addr = orig_conn_address.bind(self).call
          ipaddr = TCPSocket.getaddress(addr)
          acl.check_out_ipstring ipaddr
          return ipaddr
        end
        private :conn_address
        
        # SINGLETON HOOKS
        def __ipa_singleton_hook(acl=nil)
          self.acl = acl.nil? ? IPAccess::Global : acl
          self.acl_recheck
        end # singleton hooks
        private :__ipa_singleton_hook
        
      end # base.class_eval

    end # self.included
    
  end # module HTTP
  
end # module IPAccess::Patches

# :startdoc:

