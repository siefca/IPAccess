# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby classes in order to add
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

require 'singleton'
require 'ipaccess/ip_access_errors'

class IPAccess

  # This is global access set, used by
  # default by all socket handling
  # classes with enabled IP access control.
  
  Global = IPAccess.new 'global'

end


# This module patches network classes
# to use IP access control. Each patched 
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
  
end


