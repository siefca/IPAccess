# encoding: utf-8
#
# Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This is licensed under LGPL or Ruby License.
# 
# === ip_access_patches
# 
# Modules contained in this file are meant for
# patching Ruby socket classes in order to add
# IP access control to them.

$LOAD_PATH.unshift '..'

require 'ipaddr'
require 'socket'
require 'ipaddr_list'
require 'ipaccess/ip_access'
require 'ipaccess/ip_access_errors'

IPAccess::Global = IPAccess.new 'global'

# :stopdoc:

# This modules contain patches for Ruby socket
# classes in order to enable IP access control
# for them.
#
# This module patches socket handling classes
# to use IP access control. Each patched socket
# class has acl member, which is an IPAccess object.

module IPAccess::Patches
  
  # The IPSocketAccess module contains methods
  # that are present in all classes handling
  # sockets with IP access control enabled.

  module IPSocketAccess

    # This method enables usage of internal IP access list for object.
    # If argument is IPAccess object then it is used. If argument is other
    # kind it is assumed that it should be converted to IPAccess object
    # and give initial information about black list.
    # 
    # ==== Example
    #
    #     socket.acl = :global        # use global access lists
    #     socket.acl = :local         # create and use local access lists
    #     socket.acl = IPAccess.new   # use external (shared) access lists

    def acl=(obj)
      if obj.is_a?(Symbol)
        case obj
        when :global
          @acl = nil
        when :local
          @acl = IPAccess.new
        else
          raise ArgumentError, "bad access list selector, use: :global or :local"
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
          @acl = nil
          orig_initialize(*args)
          return self
        end

        # accept on steroids.
        define_method :accept do |*args|
          acl = @acl || IPAccess::Global
          ret = orig_accept.bind(self).call(*args)
          acl.check_in_socket(ret.first)
          return ret
        end

        # accept_nonblock on steroids.
        define_method :accept_nonblock do |*args|
          acl = @acl || IPAccess::Global
          ret = orig_accept_nonblock.bind(self).call(*args)
          acl.check_in_socket(ret.first)
          return ret
        end

        # sysaccept on steroids.
        define_method :sysaccept do |*args|
          acl = @acl || IPAccess::Global
          ret = orig_accept.bind(self).call(*args)
          acl.check_in_sockaddr(ret.last)
          return ret
        end

        # connect on steroids.
        define_method :connect do |*args|
          acl = @acl || IPAccess::Global
          acl.check_out_sockaddr(args.first)
          return orig_connect.bind(self).call(*args)
        end

        # recvfrom on steroids.
        define_method :recvfrom do |*args|
          acl = @acl || IPAccess::Global
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
          acl = @acl || IPAccess::Global
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
        
        orig_connect            = self.instance_method :connect
        orig_send               = self.instance_method :send
        orig_recvfrom           = self.instance_method :recvfrom
        orig_recvfrom_nonblock  = self.instance_method :recvfrom_nonblock
        
        # connect on steroids.
        define_method :connect do |*args|
          acl = @acl || IPAccess::Global
          peer_ip = self.class.getaddress(args.shift)
          acl.check_out_sockaddr(peer_ip)
          return orig_connect.bind(self).call(peer_ip, *args)
        end

        # send on steroids.
        define_method :send do |*args|
          hostname = args[2]
          return orig_send(*args) if hostname.nil?
          acl = @acl || IPAccess::Global
          peer_ip = self.class.getaddress(hostname)
          acl.check_out_sockaddr(peer_ip)
          args[2] = peer_ip
          return orig_send.bind(self).call(*args)
        end

        # recvfrom on steroids.
        define_method :recvfrom do |*args|
          acl = @acl || IPAccess::Global
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
          acl = @acl || IPAccess::Global
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
          acl = @acl || IPAccess::Global
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
          acl = @acl || IPAccess::Global
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
          @acl = nil
          return orig_initialize.bind(self).call(*args)
        end

        # accept on steroids.
        define_method :accept do |*args|
          acl = @acl || IPAccess::Global
          acl.check_in_socket orig_accept.bind(self).call(*args)
        end

        # accept_nonblock on steroids.
        define_method :accept_nonblock do |*args|
          acl = @acl || IPAccess::Global
          acl.check_in_socket orig_accept_nonblock.bind(self).call(*args)
        end

        # sysaccept on steroids.
        define_method :sysaccept do |*args|
          acl = @acl || IPAccess::Global
          acl.check_in_fd orig_sysaccept.bind(self).call(*args)
        end

      end # base.class_eval

    end # self.included

  end # module TCPServer

end # module IPAccess::Patches

# :startdoc:

class IPAccess
      
  # This is special method that patches Ruby's standard
  # library socket handling classes and enables
  # IP access control for them.
  # Instances of such altered classes will be
  # equipped with member called +acl+ which
  # is a kind of IPAccess and allows you to
  # manipulate access rules.
  #
  # Passed argument may be class object,
  # string representation of class object
  # or symbol representing a class object.
  # 
  # Currently supported classes are:
  # +Socket+, +UDPSocket+, +SOCKSSocket+,
  # +TCPSocket+ and +TCPServer+.
  # 
  # Example:
  # 
  #     IPAccess.arm TCPSocket                            # arm TCPSocket class  
  #     IPAccess::Global.input.blacklist 'randomseed.pl'  # add randomseed.pl to global black list
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




