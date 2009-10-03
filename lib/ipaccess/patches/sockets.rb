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
# class has acl member, which is an IPAccess object.

module IPAccess::Patches
    
  ###################################################################
  # Socket class with IP access control.
  # It uses input and output access lists.
  
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
        
        define_method :initialize do |*args|
          self.acl = :global
          orig_initialize.bind(self).call(*args)
          return self
        end

        # accept on steroids.
        define_method :accept do |*args|
          ret = orig_accept.bind(self).call(*args)
          real_acl.check_in_socket(ret.first)
          return ret
        end

        # accept_nonblock on steroids.
        define_method :accept_nonblock do |*args|
          ret = orig_accept_nonblock.bind(self).call(*args)
          real_acl.check_in_socket(ret.first)
          return ret
        end

        # sysaccept on steroids.
        define_method :sysaccept do |*args|
          ret = orig_accept.bind(self).call(*args)
          real_acl.check_in_sockaddr(ret.last)
          return ret
        end

        # connect on steroids.
        define_method :connect do |*args|
          real_acl.check_out_sockaddr(args.first)
          return orig_connect.bind(self).call(*args)
        end

        # recvfrom on steroids.
        define_method :recvfrom do |*args|
          ret = orig_recvfrom.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            real_acl.check_in_ipstring(peer_ip)
          end
          return ret
        end

        # recvfrom_nonblock on steroids.
        define_method :recvfrom_nonblock do |*args|
          ret = orig_recvfrom_nonblock.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            real_acl.check_in_ipstring(peer_ip)
          end
          return ret
        end
        
        # SINGLETON HOOKS
        def __ipa_singleton_hook(acl=nil)
          self.acl = acl
        end # singleton hooks
        private :__ipa_singleton_hook
        
      end # base.class_eval
      
    end # self.included
        
  end # module Socket
  
  ###################################################################
  # UDPSocket class with IP access control.
  # It uses input and output access lists.

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
        
        define_method :initialize do |*args|
          self.acl = :global
          orig_initialize.bind(self).call(*args)
          return self
        end
        
        # connect on steroids.
        define_method :connect do |*args|
          peer_ip = self.class.getaddress(args.shift)
          real_acl.check_out_sockaddr(peer_ip)
          return orig_connect.bind(self).call(peer_ip, *args)
        end

        # send on steroids.
        define_method :send do |*args|
          hostname = args[2]
          return orig_send.bind(self).call(*args) if hostname.nil?
          peer_ip = self.class.getaddress(hostname)
          real_acl.check_out_sockaddr(peer_ip)
          args[2] = peer_ip
          return orig_send.bind(self).call(*args)
        end

        # recvfrom on steroids.
        define_method :recvfrom do |*args|
          ret = orig_recvfrom.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            real_acl.check_in_ipstring(peer_ip)
          end
          return ret
        end

        # recvfrom_nonblock on steroids.
        define_method :recvfrom_nonblock do |*args|
          ret = orig_recvfrom_nonblock.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            real_acl.check_in_ipstring(peer_ip)
          end
          return ret
        end
        
        # SINGLETON HOOKS
        def __ipa_singleton_hook(acl=nil)
          self.acl = acl
        end # singleton hooks
        private :__ipa_singleton_hook
        
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
        define_method :initialize do |*args|
          self.acl = valid_acl?(args.last) ? args.pop : :global
          args[0] = self.class.getaddress(args[0])
          real_acl.check_out_ipstring args[0]
          orig_initialize.bind(self).call(*args)
          return self
        end
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          begin
            real_acl.check_out_socket self
          rescue IPAccessDenied
            begin
              self.close
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
        define_method :initialize do |*args|
          self.acl = valid_acl?(args.last) ? args.pop : :global
          args[0] = self.class.getaddress(args[0])
          real_acl.check_out_ipstring args[0]
          orig_initialize.bind(self).call(*args)
          return self
        end
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          begin
            real_acl.check_out_socket self
          rescue IPAccessDenied
            begin
              self.close
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
        define_method :initialize do |*args|
          self.acl = :global
          return orig_initialize.bind(self).call(*args)
        end

        # accept on steroids.
        define_method :accept do |*args|
          real_acl.check_in_socket orig_accept.bind(self).call(*args)
        end

        # accept_nonblock on steroids.
        define_method :accept_nonblock do |*args|
          real_acl.check_in_socket orig_accept_nonblock.bind(self).call(*args)
        end

        # sysaccept on steroids.
        define_method :sysaccept do |*args|
          real_acl.check_in_fd orig_sysaccept.bind(self).call(*args)
        end
        
        # this hook will be called each time @acl is reassigned
        define_method :acl_recheck do
          begin
            real_acl.check_in_socket self
          rescue IPAccessDenied
            begin
              self.close
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
      obj = obj.to_io if (defined?(OpenSSL) && (obj.is_a?(OpenSSL::SSL::SSLSocket) || obj.is_a?(OpenSSL::SSL::SSLServer)))
      case obj.class.name.to_sym
      when :TCPSocket, :UDPSocket, :TCPServer, :SOCKSSocket, :Socket
        return obj
      else
        return nil
      end
    end
    private :real_socket

    # This method tries to arm socket object.
    
    def try_arm_socket(obj, initial_acl=nil)
      late_sock = real_socket(obj)
      unless late_sock.nil?
        initial_acl = real_acl if initial_acl.nil?
        IPAccess.arm(late_sock, acl) unless late_sock.respond_to?(:acl)
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
    # If the wanted access set and the object's access
    # set is no different then acl_recheck is called
    # by force.
    #
    # This method returns the given object.
    
    def try_arm_and_check_socket(obj, initial_acl=nil)
      late_sock = real_socket(obj)
      unless late_sock.nil?
        initial_acl = real_acl if initial_acl.nil?
        IPAccess.arm(late_sock, acl) unless late_sock.respond_to?(:acl)
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
      used_acl.check_out_socket(late_sock) unless late_sock.nil?
      return obj
    end
    private :try_check_out_socket_acl

    def try_check_in_socket_acl(obj, used_acl)
      late_sock = real_socket(obj)
      used_acl.check_in_socket(late_sock) unless late_sock.nil?
      return obj
    end
    private :try_check_in_socket_acl

  end # module ACL
    
end # module IPAccess::Patches

# :startdoc:

