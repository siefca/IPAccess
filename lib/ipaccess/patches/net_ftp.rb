# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby's Net::FTP class in order to add
# IP access control to it. It is also used
# to create variant of Net::FTP class
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
require 'net/ftp'
require 'ipaccess/ip_access_errors'
require 'ipaccess/patches/generic'
require 'ipaccess/patches/sockets'

# :stopdoc:

module IPAccess::Patches::Net
  
  ###################################################################
  # Net::FTP class with IP access control.
  # It uses output and occasionally input access lists.
  
  module FTP
    
    include IPAccess::Patches::ACL
    
    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
        
        # CLASS METHODS
        unless (base.name.nil? && base.class.name == "Class")
          (class << self; self; end).class_eval do
                      
            alias :orig_open :open
            
            # overload FTP.open()
            define_method :__ipacall__open do |block, host, *args|
              late_close_on_deny = true
        	    args.delete_if { |x| late_close_on_deny = false if (x.is_a?(Symbol) && x == :opened_on_deny) }
              late_acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
              obj = orig_open(*args, &block)
              obj.acl = late_acl unless obj.acl = late_acl
              obj.close_on_deny = late_close_on_deny
              return obj
            end
            
            # block passing wrapper for Ruby 1.8
            def open(*args, &block)
              __ipacall__open(block, *args)
            end
                        
      	  end
      	
    	  end # class methods
        
        orig_initialize       = self.instance_method :initialize
        orig_open_socket      = self.instance_method :open_socket
        #orig_sendcmd          = self.instance_method :sendcmd
        orig_set_socket       = self.instance_method :set_socket
        orig_makeport         = self.instance_method :makeport
        
        # initialize on steroids.
        define_method  :__ipacall__initialize do |block, *args|
          @close_on_deny = true
          args.delete_if { |x| @close_on_deny = false if (x.is_a?(Symbol) && x == :opened_on_deny) }
          self.acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
          orig_initialize.bind(self).call(*args, &block)
        end
        
        # block passing wrapper for Ruby 1.8
        def initialize(*args, &block)
          __ipacall__initialize(block, *args)
        end
        
        # open_socket on steroids.
        define_method :open_socket do |host, port|
          host = TCPSocket.getaddress(host)
          real_acl.check_out_ipstring(host, self)
          try_arm_and_check_socket( orig_open_socket.bind(self).call(host, port) )
        end
        private :open_socket
        
        # set_socket on steroids.
        define_method :set_socket do |sock, *args|
          ret = orig_set_socket.bind(self).call(sock, args.first)
          try_arm_and_check_socket @sock
          return ret
        end
        
        # sendcmd on steroids.
        #define_method :sendcmd do |*args|
        #  acl_recheck
        #  orig_sendcmd.bind(self).call(*args)
        #end
        
        # makeport on steroids.
        define_method :makeport do
          late_sock = orig_makeport.bind(self).call
          begin
            try_arm_and_check_socket late_sock
          rescue IOError
          end
          return late_sock
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
          self.close unless self.closed?    
        end
      
      end # base.class_eval

    end # self.included
    
  end # module FTP
  
end # module IPAccess::Patches

# :startdoc:

