# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby Net::HTTP classe in order to add
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
        
        # override new() since it's not usual.
        (class << self; self; end).class_eval do
          alias_method :__new, :new
        	private :__new
        	
        	define_method :new do |*args|
        	  late_acl = :global
        	  late_acl = args.pop if IPAccess::valid_acl?(args.last)
        	  obj = __new(*args)
        	  obj.acl = late_acl if obj.respond_to?(:acl)
        	  return obj
      	  end
    	  end
        
        orig_start            = self.instance_method :start
        orig_conn_address     = self.instance_method :conn_address
        
        # start on steroids.
        define_method :start do |*args|
          if valid_acl?(args.last)
            acl = args.pop
          else
            acl = @acl.nil? ? IPAccess::Global : @acl
          end
          if (!args.first.nil? && !args.first.empty?)
            ipaddr = TCPSocket.getaddress(args.first)
            acl.check_out_ipstring ipaddr
          end
          # FIXME!!!!!!!!!!!!!!!
          # first add something that will extract IP address and test it
          # even it wasn't given as an argument
          orig_start.bind(self).call
        end
        
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

