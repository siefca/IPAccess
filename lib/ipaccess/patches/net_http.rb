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
        
        orig_conn_address     = self.instance_method :conn_address
        
        # conn_address on steroids.
        define_method :conn_address do
          acl = @acl.nil? ? IPAccess::Global : @acl
          addr = orig_conn_address.bind(self).call
          ipaddr = TCPSocket.getaddress(addr)
          acl.check_out_ipstring ipaddr
        end
        private :conn_address
        
      end # base.class_eval

    end # self.included
    
  end # module HTTP
  
end # module IPAccess::Patches

# :startdoc:

