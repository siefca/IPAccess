# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009-2014 by Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby classes in order to add
# IP access control to them.

require 'singleton'
require 'ipaccess/ip_access_errors'

module IPAccess

  class Set

    # This is global access set, used by
    # default by all socket handling
    # classes with enabled IP access control.
    # It has just one instance called IPAccess::Set.Global.
    # It is present only when patching engine is loaded.

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

      def to_s
        "#<IPAccess::Set:Global>"
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
    # the current instance is not regular IPAccess::Set object
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
  # is used. If +:opened_on_deny+ is passed then
  # any connection remains opened in case of IPAccessDenied
  # exception during arming.
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
  #     require 'ipaccess/socket'                               # load sockets subsystem and IPAccess.arm method
  # 
  #     IPAccess.arm TCPSocket                                  # arm TCPSocket class  
  #     IPAccess::Set::Global.output.blacklist 'randomseed.pl'  # add host to black list of the global set
  #     TCPSocket.new('randomseed.pl', 80)                      # try to connect
  # 
  # ==== Example 2 – HTTP
  # 
  #     require 'ipaccess/net/http'                             # load net/http subsystem and IPAccess.arm method
  # 
  #     IPAccess.arm Net::HTTP                                  # arm TCPSocket class  
  #     IPAccess::Set::Global.output.blacklist 'randomseed.pl'  # add host to black list of the global set
  #     Net::HTTP.get_print('randomseed.pl', '/i.html')         # try to connect
  # 
  # ==== Example 3 – single network object
  # 
  #     require 'ipaccess/net/telnet'                           # load Net::Telnet version and IPAccess.arm method
  # 
  #     opts = {}
  #     opts["Host"]  = 'randomseed.pl'
  #     opts["Port"]  = '80'
  #     
  #     t = Net::Telnet.new(opts)                               # try to connect to remote host
  #     
  #     acl = IPAccess::Set.new                                 # create custom access set
  #     acl.output.blacklist 'randomseed.pl'                    # blacklist host
  #     IPAccess.arm t, acl                                     # arm Telnet object and pass optional ACL
  # 
  # @overload arm(klass, acl=nil)
  # @overload arm(klass, :opened_on_deny)
  # @overload arm(klass, acl, :opened_on_deny)

  def self.arm(*args)
    cod = args.delete(:opened_on_deny).nil?
    klass, acl = *args
    singleton_obj = nil
    if klass.is_a?(Class)                                 # regular class
      klass_name = klass.name
    elsif klass.is_a?(Symbol) || klass.is_a?(String)
      klass_name = klass.to_s
      if klass.name.downcase == "sockets"                 # just a bunch of sockets
        require 'ipaccess/arm_sockets'
        return
      else                                                # regular class as a string or symbol
        klass = Kernel
        klass_name.to_s.split('::').each { |k| klass = klass.const_get(k) }
      end
    else                                                  # regular object (will patch singleton of this object)
      klass_name = klass.class.name
      singleton_obj = klass
      klass = (class <<klass; self; end)
    end
    begin
      patch_klass = IPAccess::Patches
      klass_name.split('::').each { |k| patch_klass = patch_klass.const_get(k, false) }
    rescue NameError
      raise ArgumentError, "Cannot enable IP access control for class #{klass_name}"
    end
    klass.__send__(:include, patch_klass)
    singleton_obj.__send__(:__ipa_singleton_hook, acl, cod) unless singleton_obj.nil?  # early initial check
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

      # This method returns +true+ if the current object is IPAccess::Set.Global.
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
        raise ArgumentError, "Cannot access global set from object's scope, use IPAccess::Set::Global"
      end

    end # class IPAccess::Set.GlobalSet

    # The ACL module contains methods
    # that are present in all network
    # objects with IP access control enabled.

    module ACL

      # This method is used to safely
      # pass an eventual exception
      # and fill its useables field with a current
      # object.

      def __ipa_wrap_socket_call(*args, &block)
        IPAccess.take_care(self, *args, &block)
      end
      protected :__ipa_wrap_socket_call

      # This method enables usage of internal IP access list for object.
      # If argument is IPAccess::Set object then it is used.
      # 
      # ==== Example
      #
      #     socket.acl = :global            # use global access set
      #     socket.acl = :private           # create and use individual access set
      #     socket.acl = IPAccess::Set.new  # use external (shared) access set

      def acl=(access_set)
        new_acl   = false
        prev_acl  = @acl
        if access_set.is_a?(Symbol)
          case access_set
          when :global
            new_acl = IPAccess::Set::GlobalSet.instance
          when :private
            new_acl = IPAccess::Set.new
          else
            raise ArgumentError, "Bad access list selector, use: :global or :private"
          end
        elsif access_set.is_a?(IPAccess::Set)
          new_acl = ( access_set == IPAccess::Set::Global ? IPAccess::Set::GlobalSet.instance : access_set )
        elsif access_set.nil?
          new_acl = IPAccess::Set::GlobalSet.instance
        else
          raise ArgumentError, "Bad access list"
        end
        unless (new_acl === false || prev_acl.object_id == new_acl.object_id)
          @acl = new_acl
          self.acl_recheck if self.respond_to?(:acl_recheck)
        end
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
      alias_method :access,  :acl

      # This method returns default access list indicator
      # used by protected object; usually +:input+ or
      # +:output+.

      def default_list; :output end

      # This method whitelists IP address(-es) in
      # the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess.to_cidrs.
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
      # 
      # @overload whitelist(*addresses)
      # @overload whitelist(list, *addresses)

      def whitelist(*addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = @acl.send(aclist).whitelist(*addresses)
        self.acl_recheck
        return r
      end

      alias_method :add_white,  :whitelist
      alias_method :allow,      :whitelist
      alias_method :permit,     :whitelist

      # This method works like whitelist but allows
      # to set reason.

      def whitelist_reasonable(reason, *addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = @acl.send(aclist).whitelist_reasonable(reason, *addresses)
        self.acl_recheck
        return r
      end

      # This method whitelists IP address(-es) in
      # the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess.to_cidrs.
      # This method will not add nor remove any
      # blacklisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#whitelist on the list.    
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
      # 
      # @overload whitelist!(*addresses)
      # @overload whitelist!(list, *addresses)

      def whitelist!(*addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = real_acl.send(aclist).whitelist(*addresses)
        self.acl_recheck
        return r
      end

      alias_method :add_white!,  :whitelist!
      alias_method :allow!,      :whitelist!
      alias_method :permit!,     :whitelist!

      # This method works like whitelist! but
      # allows to set reason.

      def whitelist_reasonable!(*addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = real_acl.send(aclist).whitelist_reasonable(reason, *addresses)
        self.acl_recheck
        return r
      end

      # This method removes whitelisted IP address(-es)
      # from the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess.to_cidrs.
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
      # 
      # @overload unwhitelist(*addresses)
      # @overload unwhitelist(list, *addresses)

      def unwhitelist(*addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = @acl.send(aclist).unwhitelist(*addresses)
        self.acl_recheck
        return r
      end

      alias_method :unwhite,    :unwhitelist
      alias_method :del_white,  :unwhitelist
      alias_method :unallow,    :unwhitelist
      alias_method :unpermit,   :unwhitelist

      # This method removes whitelisted IP address(-es)
      # from the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess.to_cidrs.
      # This method will not add nor remove any
      # blacklisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#unwhitelist on the list.    
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
      # 
      # @overload unwhitelist!(*addresses)
      # @overload unwhitelist!(list, *addresses)

      def unwhitelist!(*addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = real_acl.send(aclist).unwhitelist(*addresses)
        self.acl_recheck
        return r
      end

      alias_method :unwhite!,    :unwhitelist!
      alias_method :del_white!,  :unwhitelist!
      alias_method :unallow!,    :unwhitelist!
      alias_method :unpermit!,   :unwhitelist!

      # This method blacklists IP address(-es) in
      # the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess.to_cidrs.
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
      # 
      # @overload blacklist(*addresses)
      # @overload blacklist(list, *addresses)

      def blacklist(*addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = @acl.send(aclist).blacklist(*addresses)
        self.acl_recheck
        return r
      end

      alias_method :add_black,  :blacklist
      alias_method :deny,       :blacklist
      alias_method :block,      :blacklist

      # This method works like blacklist but allows to
      # set reason.

      def blacklist_reasonable(reason, *addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = @acl.send(aclist).blacklist_reasonable(reason, *addresses)
        self.acl_recheck
        return r
      end

      # This method blacklists IP address(-es) in
      # the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess.to_cidrs.
      # This method will not add nor remove any
      # whitelisted item.
      # 
      # It will return the result of calling
      # IPAccess::List#blacklist on the list.    
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
      # 
      # @overload blacklist!(*addresses)
      # @overload blacklist!(list, *addresses)

      def blacklist!(*addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = real_acl.send(aclist).blacklist(*addresses)
        self.acl_recheck
        return r
      end

      alias_method :add_black!,  :blacklist!
      alias_method :deny!,       :blacklist!
      alias_method :block!,      :blacklist!
      
      # This method works like blacklist! but allows
      # to set reason.

      def blacklist_reasonable!(reason, *addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = real_acl.send(aclist).blacklist(reason, *addresses)
        self.acl_recheck
        return r
      end

      # This method removes blacklisted IP address(-es)
      # from the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess.to_cidrs.
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
      # 
      # @overload unblacklist(*addresses)
      # @overload unblacklist(list, *addresses)

      def unblacklist(*addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = @acl.send(aclist).unblacklist(*addresses)
        self.acl_recheck
        return r
      end

      alias_method :unblack,    :unblacklist
      alias_method :undeny,     :unblacklist
      alias_method :unblock,    :unblacklist
      alias_method :del_black,  :unblacklist

      # This method removes blacklisted IP address(-es)
      # from the input or output access list selected
      # by the *list* argument (+:input+ or +:output+).
      # If the access list selector is omited it
      # operates on the default access list that certain
      # kind of network object uses. The allowed format of address
      # is the same as for IPAccess.to_cidrs.
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
      # 
      # @overload unblacklist!(*addresses)
      # @overload unblacklist!(list, *addresses)

      def unblacklist!(*addresses)
        aclist = ( addresses.first.is_a?(Symbol) && [:input,:output].include?(addresses.first) ) ? addresses.shift : self.default_list
        r = real_acl.send(aclist).unblacklist(*addresses)
        self.acl_recheck
        return r
      end

      alias_method :unblack!,   :unblacklist!
      alias_method :undeny!,    :unblacklist!
      alias_method :unblock!,   :unblacklist!
      alias_method :del_black!, :unblacklist!

      # Setting it to +false+ disables closing connection
      # when raising access denied exception

      attr_accessor :opened_on_deny

      # Setting it to +true+ disables closing connection
      # when raising access denied exception

      def close_on_deny=(x)
        self.open_on_deny = !x
      end

      def close_on_deny
        not self.open_on_deny
      end

      # This method is universal wrapper for
      # closing connection. Classes should
      # override it.

      def terminate
        self.close unless self.closed?
      end

      # This method will try to close
      # session/connection for a network object
      # if +open_on_deny+ member is set to +false+

      def try_terminate
        terminate unless @opened_on_deny
        return nil
      end
      private :try_terminate

      # helper for dropping unwanted connections
      def try_terminate_subsocket(sock)
        sock.close unless (@opened_on_deny || sock.closed?)
        return nil
      end
      private :try_terminate_subsocket

      # This method will be called when
      # instance is patched.

      def __ipa_singleton_hook(acl = nil, open_on_deny = false)
        @opened_on_deny = open_on_deny
        acl = @options["ACL"] if (acl.nil? && instance_variable_defined?(:@options) && @options.respond_to?(:has_key?))
        self.acl = acl
      end
      private :__ipa_singleton_hook

    end # module ACL
  
  end # module Patches
  
  # :startdoc:
  
end # module IPAccess
