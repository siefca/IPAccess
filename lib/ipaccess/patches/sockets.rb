# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby socket classes in order to add
# IP access control to them. It is also used
# to create variants of socket handling classes
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
require 'ipaccess/ip_access_errors'
require 'ipaccess/patches/generic'

# :stopdoc:

# This modules contain patches for Ruby socket
# classes in order to enable IP access control
# for them.
#
# This module patches socket handling classes
# to use IP access control. Each patched socket
# class has acl member, which is an IPAccess::Set object.

module IPAccess::Patches
    
  ###################################################################
  # Socket class with IP access control.
  # It uses input and output access lists.
  # Default access list for management operations is output.
  
  module Socket
    
    include IPAccess::Patches::ACL

    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do

        orig_initialize         = self.instance_method :initialize
        orig_accept             = self.instance_method :accept
        orig_accept_nonblock    = self.instance_method :accept_nonblock
        orig_connect            = self.instance_method :connect
        orig_recvfrom           = self.instance_method :recvfrom
        orig_recvfrom_nonblock  = self.instance_method :recvfrom_nonblock
        orig_sysaccept          = self.instance_method :sysaccept
        
        define_method :__ipacall__initialize do |block, *args|
          @close_on_deny = true
          args.delete_if { |x| @close_on_deny = false if (x.is_a?(Symbol) && x == :opened_on_deny) }
          self.acl = valid_acl?(args.last) ? args.pop : :global
          orig_initialize.bind(self).call(*args, &block)
          return self
        end
        
        # block passing wrapper for Ruby 1.8
        def initialize(*args, &block)
          __ipacall__initialize(block, *args)
        end

        # accept on steroids.
        define_method :accept do |*args|
          ret = orig_accept.bind(self).call(*args)
          real_acl.check_in_socket(ret.first, ret.first) { try_terminate_subsocket(ret.first) }
          return ret
        end

        # accept_nonblock on steroids.
        define_method :accept_nonblock do |*args|
          ret = orig_accept_nonblock.bind(self).call(*args)
          real_acl.check_in_socket(ret.first, ret.first)  { try_terminate_subsocket(ret.first) }
          return ret
        end

        # sysaccept on steroids.
        define_method :sysaccept do |*args|
          ret = orig_accept.bind(self).call(*args)
          real_acl.check_in_sockaddr(ret.last, ret.last) { try_terminate_subsocket(Socket.for_fd(ret.first)) }
          return ret
        end

        # connect on steroids.
        define_method :connect do |*args|
          if @close_on_deny
            real_acl.check_out_sockaddr(args.first)
            return orig_connect.bind(self).call(*args)
          else
            ret = orig_connect.bind(self).call(*args)
            real_acl.check_out_socket(ret, self)
          end
          return ret
        end

        # recvfrom on steroids.
        define_method :recvfrom do |*args|
          ret = orig_recvfrom.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            real_acl.check_in_ipstring(peer_ip, self) { try_terminate }
          end
          return ret
        end

        # recvfrom_nonblock on steroids.
        define_method :recvfrom_nonblock do |*args|
          ret = orig_recvfrom_nonblock.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            real_acl.check_in_ipstring(peer_ip, self) { try_terminate }
          end
          return ret
        end
        
        # This method returns default access list indicator
        # used by protected object; in this case it's +:output+.
        define_method :default_list do
          :output
        end
                
      end # base.class_eval
      
    end # self.included
        
  end # module Socket
  
  ###################################################################
  # UDPSocket class with IP access control.
  # It uses input and output access lists.
  # Default access list for management operations is input.

  module UDPSocket

    include IPAccess::Patches::ACL

    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
        
        orig_initialize         = self.instance_method :initialize
        orig_connect            = self.instance_method :connect
        orig_send               = self.instance_method :send
        orig_recvfrom           = self.instance_method :recvfrom
        orig_recvfrom_nonblock  = self.instance_method :recvfrom_nonblock
        
        define_method :__ipacall__initialize do |block, *args|
          self.acl = valid_acl?(args.last) ? args.pop : :global
          @close_on_deny = false
          orig_initialize.bind(self).call(*args, &block)
          return self
        end
        
        # block passing wrapper for Ruby 1.8
        def initialize(*args, &block)
          __ipacall__initialize(block, *args)
        end
        
        # connect on steroids.
        define_method :connect do |*args|
          peer_ip = self.class.getaddress(args.shift)
          real_acl.check_out_sockaddr(peer_ip, self)
          return orig_connect.bind(self).call(peer_ip, *args)
        end

        # send on steroids.
        define_method :send do |*args|
          hostname = args[2]
          return orig_send.bind(self).call(*args) if hostname.nil?
          peer_ip = self.class.getaddress(hostname)
          real_acl.check_out_sockaddr(peer_ip, self)
          args[2] = peer_ip
          return orig_send.bind(self).call(*args)
        end

        # recvfrom on steroids.
        define_method :recvfrom do |*args|
          ret = orig_recvfrom.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            real_acl.check_in_ipstring(peer_ip, self)
          end
          return ret
        end

        # recvfrom_nonblock on steroids.
        define_method :recvfrom_nonblock do |*args|
          ret = orig_recvfrom_nonblock.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            real_acl.check_in_ipstring(peer_ip, self)
          end
          return ret
        end
        
        # This method returns default access list indicator
        # used by protected object; in this case it's +:input+.
        define_method :default_list do
          :intput
        end
        
        # this kind of socket is not connection-oriented.
        define_method :connection_close do
          return nil
        end
        
      end # base.class_eval

    end # self.included

  end # module UDPSocket
  
  ###################################################################
  # SOCKSSocket class with IP access control.
  # It uses output access lists.

  module SOCKSocket

    include IPAccess::Patches::ACL

    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
    
        orig_initialize       = self.instance_method :initialize
        
        # initialize on steroids.
        define_method :__pacall__initialize do |block, *args|
          @close_on_deny = true
          args.delete_if { |x| @close_on_deny = false if (x.is_a?(Symbol) && x == :opened_on_deny) }
          self.acl = valid_acl?(args.last) ? args.pop : :global
          args[0] = self.class.getaddress(args[0])
          if @close_on_deny
            real_acl.check_out_ipstring args[0]
            orig_initialize.bind(self).call(*args, block)
          else
            orig_initialize.bind(self).call(*args, block)
            real_acl.check_out_socket(self)
          end
          return self
        end
        
        # block passing wrapper for Ruby 1.8
        def initialize(*args, &block)
          __ipacall__initialize(block, *args)
        end
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          real_acl.check_out_socket(self, self) { try_terminate }
          return nil
        end
        
        # This method returns default access list indicator
        # used by protected object; in this case it's +:output+.
        define_method :default_list do
          :output
        end
                
      end # base.class_eval

    end # self.included

  end # module SOCKSSocket

  ###################################################################
  # TCPSocket class with IP access control.
  # It uses output access lists.
  
  module TCPSocket

    include IPAccess::Patches::ACL

    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
    
        orig_initialize       = self.instance_method :initialize
        
        # initialize on steroids.
        define_method :__ipacall__initialize do |block, *args|
          @close_on_deny = true
          args.delete_if { |x| @close_on_deny = false if (x.is_a?(Symbol) && x == :opened_on_deny) }
          self.acl = valid_acl?(args.last) ? args.pop : :global
          args[0] = self.class.getaddress(args[0])
          if @close_on_deny
            real_acl.check_out_ipstring(args[0], :none)
            orig_initialize.bind(self).call(*args, &block)
          else
            orig_initialize.bind(self).call(*args, &block)
            real_acl.check_out_socket(self)
          end
          return self
        end
        
        # block passing wrapper for Ruby 1.8
        def initialize(*args, &block)
          __ipacall__initialize(block, *args)
        end
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          real_acl.check_out_socket(self, self) { try_terminate }
          return nil
        end
        
        # This method returns default access list indicator
        # used by protected object; in this case it's +:output+.
        define_method :default_list do
          :output
        end
        
      end # base.class_eval

    end # self.included

  end # module TCPSocket
  
  ###################################################################
  # TCPServer class with IP access control.
  # It uses input access lists.
  
  module TCPServer

    include IPAccess::Patches::ACL

    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
    
        orig_initialize       = self.instance_method :initialize
        orig_accept           = self.instance_method :accept
        orig_accept_nonblock  = self.instance_method :accept_nonblock
        orig_sysaccept        = self.instance_method :sysaccept
        
        # initialize on steroids.
        define_method :__ipacall__initialize do |block, *args|
          @close_on_deny = true
          args.delete_if { |x| @close_on_deny = false if (x.is_a?(Symbol) && x == :opened_on_deny) }
          self.acl = valid_acl?(args.last) ? args.pop : :global
          return orig_initialize.bind(self).call(*args, &block)
        end
        
        # block passing wrapper for Ruby 1.8
        def initialize(*args, &block)
          __ipacall__initialize(block, *args)
        end
                
        # accept on steroids.
        define_method :accept do |*args|
          r = orig_accept.bind(self).call(*args)
          real_acl.check_in_socket(r, r) { try_terminate_subsocket(r) }
          return r
        end

        # accept_nonblock on steroids.
        define_method :accept_nonblock do |*args|
          r = orig_accept_nonblock.bind(self).call(*args)
          real_acl.check_in_socket(r, r) { try_terminate_subsocket(r) }
          return r
        end
        
        # sysaccept on steroids.
        define_method :sysaccept do |*args|
          r = orig_sysaccept.bind(self).call(*args)
          real_acl.check_in_fd(r, r) { try_terminate_subsocket(Socket.for_fd(r)) }
          return r
        end
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          real_acl.check_out_socket(self, self) { try_terminate }
          return nil
        end
        
        # This method returns default access list indicator
        # used by protected object; in this case it's +:input+.
        define_method :default_list do
          :input
        end
        
      end # base.class_eval

    end # self.included

  end # module TCPServer
  
  ###################################################################
  # Helper methods for easy checking and arming sockets.

  module ACL

    # This method helps to obtain real socket object.
    # It check whether object is SOCKSSocket or SSLSocket
    # and calls the right method if needed.
    # 
    # It returns socket object or +nil+ if something went wrong.

    def real_socket(obj)
      #obj = obj.to_io if (defined?(OpenSSL) && (obj.is_a?(OpenSSL::SSL::SSLSocket) || obj.is_a?(OpenSSL::SSL::SSLServer)))
      obj = obj.io if (obj.respond_to?(:io) && obj.io.respond_to?(:getpeername))
      case obj.class.name.to_sym
      when :TCPSocket, :UDPSocket, :TCPServer, :SOCKSSocket, :Socket
        return obj
      else
        return nil
      end
    end
    private :real_socket
    
    # This method tries to arm socket object.
    # If a wanted access set and an object's access
    # set is no different then acl_recheck is called
    # by force. It sets armed socket's +close_on_deny+
    # flag to +false+.
    
    def try_arm_socket(obj, initial_acl=nil)
      late_sock = real_socket(obj)
      unless late_sock.nil?
        initial_acl = real_acl if initial_acl.nil?
        IPAccess.arm(late_sock, acl, :opened_on_deny) unless late_sock.respond_to?(:acl)
        late_sock.acl = initial_acl if late_sock.acl != initial_acl
      end
      return obj
    end
    private :try_arm_socket
    
    # This method tries to arm socket object and then
    # tries to set up correct ACL to it. If the ACL
    # had changed then it assumes underlying routines
    # took care about rechecking socket's IP against
    # correct access list (input or output). By taking
    # care we mean automatic triggering of acl_recheck
    # when object's acl= method had been called.
    # If a wanted access set and an object's access
    # set is no different then acl_recheck is called
    # by force. It sets armed socket's +close_on_deny+
    # flag to +false+.
    #
    # This method returns the given object.
    
    def try_arm_and_check_socket(obj, initial_acl=nil)
      late_sock = real_socket(obj)
      unless late_sock.nil?
        initial_acl = real_acl if initial_acl.nil?
        IPAccess.arm(late_sock, acl, :opened_on_deny) unless late_sock.respond_to?(:acl)
        if late_sock.acl != initial_acl
          late_sock.acl = initial_acl
        else
          late_sock.acl_recheck
        end
      end
      return obj
    end
    private :try_arm_and_check_socket
    
    def try_check_out_socket_acl(obj, used_acl)
      late_sock = real_socket(obj)
      used_acl.check_out_socket(late_sock, late_sock) { try_terminate } unless late_sock.nil?
      return obj
    end
    private :try_check_out_socket_acl

    def try_check_in_socket_acl(obj, used_acl)
      late_sock = real_socket(obj)
      used_acl.check_in_socket(late_sock, late_sock) { try_terminate } unless late_sock.nil?
      return obj
    end
    private :try_check_in_socket_acl

  end # module ACL
    
end # module IPAccess::Patches

# :startdoc:

