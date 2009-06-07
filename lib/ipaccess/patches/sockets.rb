# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby socket classes in order to add
# IP access control to them.
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
require 'singleton'
require 'ipaccess/ip_access_errors'

class IPAccess

  # This is global access set, used by
  # default by all socket handling
  # classes with enabled IP access control.
  
  Global = IPAccess.new 'global'

end

# :stopdoc:

# This modules contain patches for Ruby socket
# classes in order to enable IP access control
# for them.
#
# This module patches socket handling classes
# to use IP access control. Each patched socket
# class has acl member, which is an IPAccess object.

module IPAccess::Patches
  
  # This class is a proxy that raises an exception when
  # any method other than defined in Object class is called.
  # It behaves like NilClass.

  class GlobalSet
    
    include Singleton
    
    def nil?; true end
    
    def method_missing(name, *args)
      return nil.method(name).call(*args) if nil.respond_to?(name)
      raise ArgumentError, "cannot access global set from object's scope, use IPAccess::Global"
    end
    
  end
  
  
  # The IPSocketAccess module contains methods
  # that are present in all classes handling
  # sockets with IP access control enabled.

  module IPSocketAccess

    # This method enables usage of internal IP access list for object.
    # If argument is IPAccess object then it is used.
    # 
    # ==== Example
    #
    #     socket.acl = :global        # use global access set
    #     socket.acl = :private       # create and use individual access set
    #     socket.acl = IPAccess.new   # use external (shared) access set

    def acl=(obj)
      if obj.is_a?(Symbol)
        case obj
        when :global
          @acl = GlobalSet.instance
        when :private
          @acl = IPAccess.new
        else
          raise ArgumentError, "bad access list selector, use: :global or :private"
        end
      elsif obj.is_a?(IPAccess)
        @acl = obj 
      else
        raise ArgumentError, "bad access list"
      end
    end

    attr_reader :acl
    alias_method :access=, :acl=
    alias_method :access, :acl

  end
  
  ###################################################################
  # Socket class with IP access control.
  # It uses input and output access lists.
  
  module Socket
    
    include IPSocketAccess

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
          @acl = GlobalSet.instance
          orig_initialize(*args)
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

    include IPSocketAccess

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
          @acl = GlobalSet.instance
          orig_initialize(*args)
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

    include IPSocketAccess

    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
    
        orig_initialize       = self.instance_method :initialize
        
        # initialize on steroids.
        define_method :initialize do |*args|
          self.acl = (args.size > 2) ? args.pop : :global
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

    include IPSocketAccess

    def self.included(base)
      
      marker = (base.name =~ /IPAccess/) ? base.superclass : base
      return if marker.instance_variable_defined?(:@uses_ipaccess)    
      base.instance_variable_set(:@uses_ipaccess, true)
      
      base.class_eval do
    
        orig_initialize       = self.instance_method :initialize
        
        # initialize on steroids.
        define_method :initialize do |*args|
          self.acl = (args.size > 2) ? args.pop : :global
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

    include IPSocketAccess

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
          @acl = GlobalSet.instance
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

class IPAccess
  
  # This special method patches Ruby's standard
  # library socket handling classes and enables
  # IP access control for them. Instances of
  # such altered classes will be equipped with
  # member called +acl+ which is a kind of
  # IPAccess and allows you to manipulate
  # access rules.
  #
  # Passed argument may be a class object,
  # a string representation of a class object
  # or a symbol representing a class object.
  # 
  # Currently supported classes are:
  # +Socket+, +UDPSocket+, +SOCKSSocket+,
  # +TCPSocket+ and +TCPServer+.
  # 
  # Example:
  # 
  #     require 'ipaccess/socket'                         # load sockets subsystem and IPAccess.arm method
  # 
  #     IPAccess.arm TCPSocket                            # arm TCPSocket class  
  #     IPAccess::Global.output.blacklist 'randomseed.pl' # add host to black list of the global set
  #     TCPSocket.new('randomseed.pl', 80)                # try to connect
  
  def self.arm(klass)
    klass_name = klass.name if klass.is_a?(Class)
    klass_name = klass_name.to_s unless klass.is_a?(String)
    klass_name = klass_name.to_sym
    case klass_name
    when :Socket, :UDPSocket, :SOCKSSocket, :TCPSocket, :TCPServer
      klass.__send__(:include, Patches.const_get(klass_name))
    else
      raise ArgumentError, "cannot enable IP access control for class #{klass_name}"
    end
  end
  
end

