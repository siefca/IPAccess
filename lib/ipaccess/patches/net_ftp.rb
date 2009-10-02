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
  # It uses output access lists.
  
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
              late_acl = IPAccess.valid_acl?(args.last) ? args.pop : :global
              obj = orig_open(*args, &block)
              obj.acl = late_acl unless obj.acl = late_acl
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
        orig_makeport         = self.instance_method :makeport
        
        # initialize on steroids
        define_method  :__ipacall__initialize do |block, *args|
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
          real_acl.check_out_ipstring host
          late_sock = orig_open_socket.bind(self).call(host, port)
          if (late_sock.is_a?(TCPSocket) || (Object.const_defined?(:SOCKSSocket) && late_sock.is_a?(SOCKSSocket)))
            IPAccess.arm(late_sock, acl) unless late_sock.respond_to?(:acl)
            late_sock.acl = self.acl if late_sock.acl != self.acl
          end
          return late_sock
        end
        private :open_socket
        
        # sendcmd on steroids.
        #define_method :sendcmd do |*args|
        #  acl_recheck
        #  orig_sendcmd.bind(self).call(*args)
        #end
        
        # makeport on steroids.
        define_method :makeport do
          late_sock = orig_makeport.bind(self).call
          if (late_sock.is_a?(TCPServer) || late_sock.is_a?(TCPSocket))
            IPAccess.arm(late_sock, acl) unless late_sock.respond_to?(:acl)
            late_sock.acl = self.acl if late_sock.acl != self.acl # share socket's access set with Net::HTTP object
          end
          return late_sock
        end
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          begin
            late_sock = @sock
            real_acl.check_out_socket late_sock
          rescue IPAccessDenied
            begin
              self.close
            rescue IOError
            end
            raise
          end
          if (late_sock.is_a?(TCPSocket) || (Object.const_defined?(:SOCKSSocket) && late_sock.is_a?(SOCKSSocket)))
            IPAccess.arm(late_sock, acl) unless late_sock.respond_to?(:acl)
            late_sock.acl = self.acl if late_sock.acl != self.acl # share socket's access set with Net::FTP object
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
    
  end # module FTP
  
end # module IPAccess::Patches

# :startdoc:

