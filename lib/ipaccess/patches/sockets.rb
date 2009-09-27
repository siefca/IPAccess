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
          @acl = IPAccess::GlobalSet.instance
          orig_initialize.bind(self).call(*args)
          return self
        end

        # accept on steroids.
        define_method :accept do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          ret = orig_accept.bind(self).call(*args)
          acl.check_in_socket(ret.first)
          return ret
        end

        # accept_nonblock on steroids.
        define_method :accept_nonblock do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          ret = orig_accept_nonblock.bind(self).call(*args)
          acl.check_in_socket(ret.first)
          return ret
        end

        # sysaccept on steroids.
        define_method :sysaccept do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          ret = orig_accept.bind(self).call(*args)
          acl.check_in_sockaddr(ret.last)
          return ret
        end

        # connect on steroids.
        define_method :connect do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          acl.check_out_sockaddr(args.first)
          return orig_connect.bind(self).call(*args)
        end

        # recvfrom on steroids.
        define_method :recvfrom do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          ret = orig_recvfrom.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            acl.check_in_ipstring(peer_ip)
          end
          return ret
        end

        # recvfrom_nonblock on steroids.
        define_method :recvfrom_nonblock do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          ret = orig_recvfrom_nonblock.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            acl.check_in_ipstring(peer_ip)
          end
          return ret
        end
        
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
          @acl = IPAccess::GlobalSet.instance
          orig_initialize.bind(self).call(*args)
          return self
        end
        
        # connect on steroids.
        define_method :connect do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          peer_ip = self.class.getaddress(args.shift)
          acl.check_out_sockaddr(peer_ip)
          return orig_connect.bind(self).call(peer_ip, *args)
        end

        # send on steroids.
        define_method :send do |*args|
          hostname = args[2]
          return orig_send(*args) if hostname.nil?
          acl = @acl.nil? ? IPAccess::Global : @acl
          peer_ip = self.class.getaddress(hostname)
          acl.check_out_sockaddr(peer_ip)
          args[2] = peer_ip
          return orig_send.bind(self).call(*args)
        end

        # recvfrom on steroids.
        define_method :recvfrom do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          ret = orig_recvfrom.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            acl.check_in_ipstring(peer_ip)
          end
          return ret
        end

        # recvfrom_nonblock on steroids.
        define_method :recvfrom_nonblock do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          ret = orig_recvfrom_nonblock.bind(self).call(*args)
          peer_ip = ret[1][3]
          family = ret[1][0]
          if (family == "AF_INET" || family == "AF_INET6")
            acl.check_in_ipstring(peer_ip)
          end
          return ret
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
        define_method :initialize do |*args|
          self.acl = valid_acl?(args.last) ? args.pop : :global
          acl = @acl.nil? ? IPAccess::Global : @acl
          args[0] = self.class.getaddress(args[0])
          acl.check_out_ipstring args[0]
          orig_initialize.bind(self).call(*args)
          return self
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
        define_method :initialize do |*args|
          self.acl = valid_acl?(args.last) ? args.pop : :global
          acl = @acl.nil? ? IPAccess::Global : @acl
          args[0] = self.class.getaddress(args[0])
          acl.check_out_ipstring args[0]
          orig_initialize.bind(self).call(*args)
          return self
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
        define_method :initialize do |*args|
          @acl = IPAccess::GlobalSet.instance
          return orig_initialize.bind(self).call(*args)
        end

        # accept on steroids.
        define_method :accept do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          acl.check_in_socket orig_accept.bind(self).call(*args)
        end

        # accept_nonblock on steroids.
        define_method :accept_nonblock do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          acl.check_in_socket orig_accept_nonblock.bind(self).call(*args)
        end

        # sysaccept on steroids.
        define_method :sysaccept do |*args|
          acl = @acl.nil? ? IPAccess::Global : @acl
          acl.check_in_fd orig_sysaccept.bind(self).call(*args)
        end

      end # base.class_eval

    end # self.included

  end # module TCPServer
  
end # module IPAccess::Patches

# :startdoc:

