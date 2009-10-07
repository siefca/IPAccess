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

module IPAccess

  class Set

    # This is global access set, used by
    # default by all socket handling
    # classes with enabled IP access control.
    # It is present as single instance called IPAccess::Set.Global
    # only when patching engine is loaded.

    class GlobalClass < Set
      
      # :stopdoc:
      
      include Singleton

      def global?; true end
      
      def ==(obj)
        return true if obj.object_id == IPAccess::Set::GlobalSet.instance.object_id
        super(obj)
      end

      def ===(obj)
        return true if obj.object_id == IPAccess::Set::GlobalSet.instance.object_id
        super(obj)
      end
                
      # :startdoc:
    
    end

    # This is global access set, used by
    # default by all socket handling
    # classes with enabled IP access control.
    # It is present only when patching engine is loaded.
    
    Global = GlobalClass.instance
    Global.name = 'global'
    
    # This method returns +true+ when
    # the current instance is not real IPAccess::Set object
    # but a reference to the IPAccess::Set.Global,
    # which should be reached by that name. It returns
    # +false+ in case of regular IPAccess::Set objects.
    # 
    # This method is present only if
    # patching engine had been loaded.
    
    def global?; false end
        
  end # class Set
  
  # This special method patches Ruby's standard
  # library classes and enables IP access control
  # for them. Instances of such altered classes
  # will be equipped with member called +acl+,
  # which is a kind of IPAccess::Set and allows you
  # to manipulate access rules. It is also
  # able to patch single instance of supported
  # classes.
  #
  # This method returns object that has
  # been patched.
  #
  # ==== Supported classes
  #  
  # Currently supported classes are:
  # 
  #   – Socket, UDPSocket, SOCKSSocket, TCPSocket, TCPServer,
  #   – Net::HTTP,
  #   – Net::Telnet,
  #   – Net::FTP,
  #   – Net::POP3,
  #   – Net::IMAP,
  #   – Net::SMTP.
  #
  # ==== Patching classes
  # 
  # Passed argument may be a class object,
  # a string representation of a class object
  # or a symbol representing a class object.
  #
  # ==== Patching single instances
  # 
  # Passed argument may be an instance of
  # supported class. It's possible to
  # pass second, optional argument, which
  # should be an initial access set. If
  # this argument is omited then IPAccess::Set.Global
  # is used. 
  # 
  # ==== Patching Ruby's sockets
  # 
  # To quickly patch all Ruby's socket classes
  # you may pass symbol +:sockets+ as an
  # argument.
  # 
  # === Examples
  #
  # ==== Example 1 – sockets
  # 
  #     require 'ipaccess/socket'                         # load sockets subsystem and IPAccess.arm method
  # 
  #     IPAccess.arm TCPSocket                            # arm TCPSocket class  
  #     IPAccess::Set.Global.output.blacklist 'randomseed.pl' # add host to black list of the global set
  #     TCPSocket.new('randomseed.pl', 80)                # try to connect
  # 
  # ==== Example 2 – HTTP
  # 
  #     require 'ipaccess/net/http'                       # load net/http subsystem and IPAccess.arm method
  # 
  #     IPAccess.arm Net::HTTP                            # arm TCPSocket class  
  #     IPAccess::Set.Global.output.blacklist 'randomseed.pl' # add host to black list of the global set
  #     Net::HTTP.get_print('randomseed.pl', '/i.html')   # try to connect
  # 
  # ==== Example 3 – single network object
  # 
  #     require 'ipaccess/net/telnet'                     # load Net::Telnet version and IPAccess.arm method
  # 
  #     opts = {}
  #     opts["Host"]  = 'randomseed.pl'
  #     opts["Port"]  = '80'
  #     
  #     t = Net::Telnet.new(opts)                         # try to connect to remote host
  #     
  #     acl = IPAccess::Set.new                                # create custom access set
  #     acl.output.blacklist 'randomseed.pl'              # blacklist host
  #     IPAccess.arm t, acl                               # arm Telnet object and pass optional ACL
  
  def self.arm(klass, acl=nil)
    singleton_obj = nil
    if klass.is_a?(Class)                                 # regular class
      klass_name = klass.name 
    elsif (klass.is_a?(Symbol) || klass.is_a?(String))
      klass_name = klass.to_s
      if klass.name.downcase == "sockets"                 # just a bunch of sockets
        require 'ipaccess/arm_sockets'
        return
      else                                                # regular class as a string or symbol
        klass = Kernel
        klass_name.to_s.split('::').each do |k|
          klass = klass.const_get(k)
        end
      end
    else                                                  # regular object (will patch singleton of this object)
      klass_name = klass.class.name
      singleton_obj = klass
      klass = (class <<klass; self; end)
    end
    begin
      patch_klass = IPAccess::Patches
      klass_name.split('::').each do |k|
        patch_klass = patch_klass.const_get(k)
      end
    rescue NameError
      raise ArgumentError, "cannot enable IP access control for class #{klass_name}"
    end
    klass.__send__(:include, patch_klass)
    singleton_obj.__send__(:__ipa_singleton_hook, acl) unless singleton_obj.nil?
    return klass
  end
  
  # :stopdoc:
  
  # This module patches network classes
  # to enforce IP access control for them. Each patched 
  # class has the acl member, which is an IPAccess::Set object.

  module Patches
  
    # This class is a proxy that raises an exception when
    # any method other than defined in Object class is called.
    # It behaves like NilClass. Do not use this class, use
    # IPAccess::Set.Global constant instead.

    class IPAccess::Set::GlobalSet
    
      include Singleton

      # imitate nil
      def nil?; true end
      
      # This method returns +true+ if current object is IPAccess::Set.Global.
      # Otherwise it returns +false+.
      def global?; true end
      
      # return +true+ when compared to IPAccess::Set.Global
      def ==(obj)
        return true if obj.object_id == IPAccess::Set::Global.object_id
        method_missing(:==, obj)
      end
      
      def ===(obj)
        return true if obj.object_id == IPAccess::Set::Global.object_id
        method_missing(:===, obj)
      end
      
      # imitate IPAccess::Set.Global when inspected
      def inspect
        IPAccess::Set::Global.inspect
      end
      
      # imitate nil even more and disallow direct ACL modifications
      def method_missing(name, *args)
        return nil.method(name).call(*args) if nil.respond_to?(name)
        raise ArgumentError, "cannot access global set from object's scope, use IPAccess::Set::Global"
      end
      
  end # class IPAccess::Set.GlobalSet

    # The ACL module contains methods
    # that are present in all network
    # objects with IP access control enabled.
  
    module ACL

      # This method enables usage of internal IP access list for object.
      # If argument is IPAccess::Set object then it is used.
      # 
      # ==== Example
      #
      #     socket.acl = :global        # use global access set
      #     socket.acl = :private       # create and use individual access set
      #     socket.acl = IPAccess::Set.new   # use external (shared) access set
      
      def acl=(obj)
        if obj.is_a?(Symbol)
          case obj
          when :global
            @acl = IPAccess::Set::GlobalSet.instance
          when :private
            @acl = IPAccess::Set.new
          else
            raise ArgumentError, "bad access list selector, use: :global or :private"
          end
        elsif obj.is_a?(IPAccess::Set)
          if obj == IPAccess::Set::Global
            @acl = IPAccess::Set::GlobalSet.instance
          else
            @acl = obj
          end
        elsif obj.nil?
          @acl = IPAccess::Set::GlobalSet.instance
        else
          raise ArgumentError, "bad access list"
        end
        self.acl_recheck if self.respond_to?(:acl_recheck)
      end
    
        # This method returns +true+ if the given object can be used to initialize ACL.
        # Otherwise it returns +false+.
        
        def IPAccess.valid_acl?(obj)
          if obj.is_a?(Symbol)
            return true if (obj == :global || obj == :private)
          elsif obj.is_a?(IPAccess::Set)
            return true
          end
          return false
        end
        
        # This method returns +true+ if the given object can be used to initialize ACL.
        # Otherwise it returns +false+.
            
        def valid_acl?(obj)
          IPAccess.valid_acl?(obj)
        end
        
        # This method should be called each time the access set related to an object
        # is changed and there is a need to validate remote peer again, since it might be
        # blacklisted.
        # 
        # Each class that patches Ruby's network class should redefine this method
        # and call it in a proper place (e.g. from hook executed when singleton methods
        # are added to network object).
        
        def acl_recheck
          ;
        end
    
      # This method return current access set for an object.
      # 
      # Ifaccess set (@acl) is somehow set to +nil+
      # (which should never happend) or to IPAccess::Set.GlobalSet
      # (which is internal singleton used to mark that @acl should
      # point to the global set) it will return a reference
      # to the global access set IPAccess::Set.Global.
      
      def real_acl
        @acl.nil? ? IPAccess::Set::Global : @acl
      end
      private :real_acl
      
      attr_reader :acl
      alias_method :access=, :acl=
      alias_method :access, :acl
      
      # This method returns default access list indicator
      # used by protected object; usually +:input+ or
      # +:output+.
    
      def default_list; :output end
      
      # :call-seq:
      #   whitelist(list, *addresses)
      #   whitelist(*addresses)
      # 
      # This method whitelists IP address(-es) in
      # the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess::List.obj_to_cidr.
      # This method will not add nor remove any
      # blacklisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#whitelist on the list.    
      # 
      # This method won't allow you to modify the list if
      # the global access set is associated with an object.
      # You may operate on IPAccess::Set.Global or use
      # whitelist! instead.
      # 
      #
      #
      # === Revalidation
      #
      # After modyfing access set current connection
      # is validated again to avoid access leaks.
      # 
      # === DNS Warning
      #
      # You should avoid passing hostnames as arguments since
      # DNS is not reliable and responses may change with time,
      # which may cause security flaws.

      def whitelist(*args)
        aclist = ( args.first.is_a?(Symbol) && [:input,:output].include?(args.first) ) ? args.shift : self.default_list
        r = @acl.send(aclist).whitelist(*args)
        self.acl_recheck
        return r
      end
      
      alias_method :add_white,  :whitelist
      alias_method :allow,      :whitelist
      alias_method :permit,     :whitelist
      
      # :call-seq:
      #   whitelist!(list, *addresses)
      #   whitelist!(*addresses)
      # 
      # This method whitelists IP address(-es) in
      # the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess::List.obj_to_cidr.
      # This method will not add nor remove any
      # blacklisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#whitelist on the list.    
      # 
      # This method will allow you to modify the list
      # even if the global access set is used by object.
      # 
      #
      #
      # === Revalidation
      #
      # After modyfing access set current connection
      # is validated again to avoid access leaks.
      # 
      # === DNS Warning
      #
      # You should avoid passing hostnames as arguments since
      # DNS is not reliable and responses may change with time,
      # which may cause security flaws.

      def whitelist!(*args)
        aclist = ( args.first.is_a?(Symbol) && [:input,:output].include?(args.first) ) ? args.shift : self.default_list
        r = real_acl.send(aclist).whitelist(*args)
        self.acl_recheck
        return r
      end
      
      alias_method :add_white!,  :whitelist!
      alias_method :allow!,      :whitelist!
      alias_method :permit!,     :whitelist!
      
      # :call-seq:
      #   unwhitelist(list, *addresses)
      #   unwhitelist(*addresses)
      # 
      # This method removes whitelisted IP address(-es)
      # from the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess::List.obj_to_cidr.
      # This method will not add nor remove any
      # blacklisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#unwhitelist on the list.    
      # 
      # This method won't allow you to modify the list if
      # the global access set is associated with an object.
      # You may operate on IPAccess::Set.Global or use
      # unwhitelist! instead.
      # 
      #
      #
      # === Revalidation
      #
      # After modyfing access set current connection
      # is validated again to avoid access leaks.
      # 
      # === DNS Warning
      #
      # You should avoid passing hostnames as arguments since
      # DNS is not reliable and responses may change with time,
      # which may cause security flaws.
      
      def unwhitelist(*args)
        aclist = ( args.first.is_a?(Symbol) && [:input,:output].include?(args.first) ) ? args.shift : self.default_list
        r = @acl.send(aclist).unwhitelist(*args)
        self.acl_recheck
        return r
      end
      
      alias_method :unwhite,    :unwhitelist
      alias_method :del_white,  :unwhitelist
      alias_method :unallow,    :unwhitelist
      alias_method :unpermit,   :unwhitelist
      
      # :call-seq:
      #   unwhitelist!(list, *addresses)
      #   unwhitelist!(*addresses)
      # 
      # This method removes whitelisted IP address(-es)
      # from the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess::List.obj_to_cidr.
      # This method will not add nor remove any
      # blacklisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#unwhitelist on the list.    
      # 
      # This method will allow you to modify the list
      # even if the global access set is used by object.
      # 
      #
      #
      # === Revalidation
      #
      # After modyfing access set current connection
      # is validated again to avoid access leaks.
      # 
      # === DNS Warning
      #
      # You should avoid passing hostnames as arguments since
      # DNS is not reliable and responses may change with time,
      # which may cause security flaws.
      
      def unwhitelist!(*args)
        aclist = ( args.first.is_a?(Symbol) && [:input,:output].include?(args.first) ) ? args.shift : self.default_list
        r = real_acl.send(aclist).unwhitelist(*args)
        self.acl_recheck
        return r
      end
      
      alias_method :unwhite!,    :unwhitelist!
      alias_method :del_white!,  :unwhitelist!
      alias_method :unallow!,    :unwhitelist!
      alias_method :unpermit!,   :unwhitelist!
      
      # :call-seq:
      #   blacklist(list, *addresses)
      #   blacklist(*addresses)
      # 
      # This method blacklists IP address(-es) in
      # the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess::List.obj_to_cidr.
      # This method will not add nor remove any
      # whitelisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#blacklist on the list.    
      # 
      # This method won't allow you to modify the list if
      # the global access set is associated with an object.
      # You may operate on IPAccess::Set.Global or use
      # blacklist! instead.
      # 
      #
      #
      # === Revalidation
      #
      # After modyfing access set current connection
      # is validated again to avoid access leaks.
      # 
      # === DNS Warning
      #
      # You should avoid passing hostnames as arguments since
      # DNS is not reliable and responses may change with time,
      # which may cause security flaws.
          
      def blacklist(*args)
        aclist = ( args.first.is_a?(Symbol) && [:input,:output].include?(args.first) ) ? args.shift : self.default_list
        r = @acl.send(aclist).blacklist(*args)
        self.acl_recheck
        return r
      end
      
      alias_method :add_black,  :blacklist
      alias_method :deny,       :blacklist
      alias_method :block,      :blacklist
      
      # :call-seq:
      #   blacklist!(list, *addresses)
      #   blacklist!(*addresses)
      # 
      # This method blacklists IP address(-es) in
      # the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess::List.obj_to_cidr.
      # This method will not add nor remove any
      # whitelisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#blacklist on the list.    
      # 
      # This method will allow you to modify the list
      # even if the global access set is used by object.
      # 
      #
      #
      # === Revalidation
      #
      # After modyfing access set current connection
      # is validated again to avoid access leaks.
      # 
      # === DNS Warning
      #
      # You should avoid passing hostnames as arguments since
      # DNS is not reliable and responses may change with time,
      # which may cause security flaws.
      
      def blacklist!(*args)
        aclist = ( args.first.is_a?(Symbol) && [:input,:output].include?(args.first) ) ? args.shift : self.default_list
        r = real_acl.send(aclist).blacklist(*args)
        self.acl_recheck
        return r
      end
      
      alias_method :add_black!,  :blacklist!
      alias_method :deny!,       :blacklist!
      alias_method :block!,      :blacklist!
      
      # :call-seq:
      #   unblacklist(list, *addresses)
      #   unblacklist(*addresses)
      # 
      # This method removes blacklisted IP address(-es)
      # from the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess::List.obj_to_cidr.
      # This method will not add nor remove any
      # whitelisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#unblacklist on the list.    
      # 
      # This method won't allow you to modify the list if
      # the global access set is associated with an object.
      # You may operate on IPAccess::Set.Global or use
      # unwhitelist! instead.
      # 
      #
      #
      # === Revalidation
      #
      # After modyfing access set current connection
      # is validated again to avoid access leaks.
      # 
      # === DNS Warning
      #
      # You should avoid passing hostnames as arguments since
      # DNS is not reliable and responses may change with time,
      # which may cause security flaws.
      
      def unblacklist(*args)
        aclist = ( args.first.is_a?(Symbol) && [:input,:output].include?(args.first) ) ? args.shift : self.default_list
        r = @acl.send(aclist).unblacklist(*args)
        self.acl_recheck
        return r
      end
      
      alias_method :unblack,    :unblacklist
      alias_method :undeny,     :unblacklist
      alias_method :unblock,    :unblacklist
      alias_method :del_black,  :unblacklist
      
      # :call-seq:
      #   unblacklist!(list, *addresses)
      #   unblacklist!(*addresses)
      # 
      # This method removes blacklisted IP address(-es)
      # from the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess::List.obj_to_cidr.
      # This method will not add nor remove any
      # whitelisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#unblacklist on the list.    
      # 
      # This method will allow you to modify the list
      # even if the global access set is used by object.
      # 
      # === Revalidation
      #
      # After modyfing access set current connection
      # is validated again to avoid access leaks.
      # 
      # === DNS Warning
      #
      # You should avoid passing hostnames as arguments since
      # DNS is not reliable and responses may change with time,
      # which may cause security flaws.
      
      def unblacklist!(*args)
        aclist = ( args.first.is_a?(Symbol) && [:input,:output].include?(args.first) ) ? args.shift : self.default_list
        r = real_acl.send(aclist).unblacklist(*args)
        self.acl_recheck
        return r
      end
      
      alias_method :unblack!,   :unblacklist!
      alias_method :undeny!,    :unblacklist!
      alias_method :unblock!,   :unblacklist!
      alias_method :del_black!, :unblacklist!

    end # module ACL
  
  end # module Patches
  
  # :startdoc:
  
end # module IPAccess


