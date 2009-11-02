# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# This file contains IPAccess::List class, which uses
# NetAddr::Tree to implement IP access list.
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

require 'socket'
require 'resolv'
require 'netaddr'
require 'ipaccess'
require 'ipaccess/patches/netaddr'

module IPAccess
  
  # This class stores information about
  # references to collection of objects and
  # allows to call specified method on them.
  
  class Bus

    def initialize
      @bus = {}
    end

    # This method attaches objects to a special bus
    # that allows them to be notified about any
    # changes in an access list. The object must
    # respond to acl_recheck since it will be
    # called.
    
    def attach(*objects)
      objects.each do |obj|
        if obj.respond_to?(:acl_recheck)
          @bus[obj.object_id] = obj.class.name.to_sym
        else
          raise ArgumentError, "attached object must respond to acl_recheck"
        end
      end
      return nil
    end
    
    # This method detaches given objects from collection.
    
    def detach(*objects)
      objects.each do |obj|
        @bus.delete obj.object_id  
      end
      return nil
    end
    
    # This method calls acl_recheck
    # for any object that is attached to a bus.
    
    def call
      ecol = IPAccessDenied::Aggregate.new
      @bus.delete_if do |o_id, o_klass|
        obj = ObjectSpace.id2ref o_id
        if (obj.class.name.to_sym == o_klass && obj.respond_to?(:acl_recheck))
          begin
            obj.acl_recheck
          rescue IPAccessDenied => e
            ecol.push e
          end
          false
        else
          true
        end
      end # delete_if
      if block_given?
        ecol.each { |e| yield e }
      else
        raise ecol unless ecol.empty?
      end
      return nil
    end
    
  end

  # This class maintains a simple access list containing two lists of rules.
  # 
  # === Access lists
  # 
  # IPAccess::List objects contain two <b>lists of rules</b>:
  # a <b>white list</b> and a <b>black list</b>. You can add IP rules
  # (both IPv4 and IPv6) to these lists. *Rules* are IP
  # addresses with netmasks, internally keept as NetAddr::CIDR
  # objects.
  # 
  # === Rules management
  # 
  # The class provides methods for easy administration
  # of lists and makes use of method IPAccess.to_cidrs that
  # "understands" most common IP representations including
  # DNS names, sockets, file descriptors bound to sockets and more.
  # 
  # === Checking access
  # 
  # You may check access for provided IP addresses against
  # white and black lists using proper methods. An address will match
  # if it's in a range of defined rule.
  # 
  # Access is evaluated as denied when tested IP
  # address matches rule from black list and not
  # matches any rule from white list.
  # In other words: white list has precedence over black list.
  # If an IP address doesn't match any rule from any list then
  # methods evaluating access permit it. The default policy is
  # to accept. To change the default policy you may want to add
  # +:all+ rule to a black list, which would match all addresses,
  # then just whitelist permitted.
  #
  # === IPv4 and IPv6
  # 
  # IPv6 addresses that are IPv4 compatible
  # or IPv4 masked are automatically
  # translated into IPv4 addresses while
  # adding or searching.
  #
  # === Examples
  # 
  # ==== Simple usage
  #
  #     access = IPAccess::List.new           # create new access list
  #     access.blacklist :ipv4_private      # blacklist private IPv4 addresses
  #     access.whitelist '172.16.0.7'       # whitelist 172.16.0.7
  #     access.granted? '172.16.0.7'        # check access
  #     access.granted? '172.16.0.1'        # check access
  #     access.delete :black, '172.16.0.1'  # remove 172.16.0.1 from blacklist 
  #     access.granted? '172.16.0.1'        # check access
  #
  # ==== Deny-all & allow-selected strategy:
  # 
  #     access = IPAccess::List.new       # create new access list
  #     access.deny :all                # blacklist all
  #     access.allow '192.168.1.0/24'   # allow my private network
  #     access.allow :local             # allow localhost
  #     
  #     puts access.show                # display internal structure
  #     puts access.blacklist           # display blacklisted IP addresses
  #     puts access.whitelist           # display whitelisted IP addresses
  
  class List < NetAddr::Tree
    
    # This attribute contains IPAccess::Bus object
    # that allows network objects to register themselves
    # in order to be notified when list is changed.
    
    attr_accessor :bus
    
    # Creates new IPAccess::List object. You may pass objects
    # (containing IP information) to it. These objects will
    # create black list rules. See IPAccess.to_cidrs description
    # for more info on how to pass arguments.
    #
    # IPAccess::List object and/or NetAddr::CIDR object(s) may
    # carry black or white list assignments inside. If such
    # object(s) will be used to create initial ruleset then
    # assignment found there would be used instead of default. 
    #
    # You should avoid passing hostnames as arguments since
    # DNS is not reliable and responses may change with time,.
    # That may cause security flaws.
    # 
    # ==== Examples
    #     
    #     IPAccess::List.new '192.168.0.0/16', '127.0.0.1/255.0.0.0'
    #     IPAccess::List.new :private, :local
    #     IPAccess::List.new "randomseed.pl", :nonpublic
    
    def initialize(*addresses)
      addresses = [] if addresses == [nil]
      @bus = IPAccess::Bus.new
      super()
      add!(*addresses) unless addresses.empty?
      return self
    end
    
    # This method finds all matching addresses in the list
    # and returns an array containing these addresses.
    # If the optional block is supplied, each matching element
    # is passed to it, and the block‘s result is stored
    # in the output array.
    #
    # Ba aware that it may call the block for same object twice
    # if you'll pass two matching addresses.
    #
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def grep(*addresses)
      return [] if empty?
      out_ary = []
      addrs = IPAccess.to_cidrs(*addresses)
      addrs.each do |addr|
        m = included_cidr(addr)
        out_ary.push( block_given? ? yield(m) : m) unless m.nil?
      end
      return out_ary
    end
    
    alias_method :search, :grep
    
    # This method finds all addresses in the list that are
    # equal to given addresses/netmasks and returns an array containing
    # these addresses. It is intended to be used to operate on
    # lists rather than to match IPs to them.
    # 
    # If the optional block is supplied,
    # each matching element is passed to it, and the block‘s
    # result is stored in the output array.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def grep_exact(*addresses)
      return [] if empty?
      out_ary = []
      addrs = IPAccess.to_cidrs(*addresses)
      addrs.each do |addr|
        m = included_cidr(addr)
        if (m == addr)
          out_ary.push( block_given? ? yield(m) : m)
        end
      end
      return out_ary
    end
      
    # This method adds new rule(s) to access list. By default
    # elements are added to black list. If first or last argument
    # is +:white+ or +:black+ then element is added to the specified
    # list.
    # 
    # If the given rule is exact (IP and mask) as pre-existent
    # rule in the same access list then it is not added.
    # 
    # You should avoid passing hostnames as arguments since
    # DNS is not reliable and responses may change with time,
    # which may cause security flaws.
    #
    # Special case: some CIDR objects may carry information about
    # access list they should belong to. If the last argument
    # of this method does not specify access list and added rule
    # is the kind of special CIDR containing information about
    # assignment to some list then this extra sugar will be used
    # in assignment instead of default +:black+. These special
    # CIDR object are usualy result of passing IPAccess::List
    # as an argument. To be sure, whichaccess
    # list will be altered always give its name when passing
    # IPAccess::List.
    #  
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def add!(*addresses)
      add_core(nil, *addresses)
    end
    
    alias_method :add, :add!
    
    # This method works the same way as add! but allows
    # you to add a reason that will be stored with an
    # element.
    
    def add_reasonable!(reason, *addresses)
      add_core(reason, *addresses)
    end
    
    alias_method :add_reasonable, :add_reasonable!
    
    # This is core adding method.
    
    def add_core(reason, *addresses, &block)
      acl_list = nil
      acl_list = addresses.shift if (addresses.first.is_a?(Symbol) && (addresses.first == :white || addresses.first == :black))
      acl_list = addresses.pop if (addresses.last.is_a?(Symbol) && (addresses.last == :white || addresses.last == :black))
      return nil if addresses.empty?
      added = false
      addrs = IPAccess.to_cidrs(*addresses)
      addrs.each do |addr|
        addr = addr.ipv4 if addr.ipv4_compliant?
        add_list = acl_list.nil? ? addr.tag[:ACL] : acl_list  # object with extra sugar
        add_list = :black if add_list.nil?
        unless reason.to_s.empty?
          reason_tag = ("Reason_" + add_list.to_s).to_sym
          reason = reason.to_s.to_sym
        end
        exists = find_me(addr)
        if exists.nil?
          addr.tag[:Subnets] = []
          addr.tag[:ACL] = add_list
          addr.tag[reason_tag] = reason unless reason.to_s.empty?
          add_to_tree(addr)
          added = true
        elsif exists.tag[:ACL] != add_list
          exists.tag[:ACL] = :grey
          exists.tag[reason_tag] = reason unless reason.to_s.empty?
          added = true
        end
      end
      @bus.call(&block) if added
      return nil
    end
    private :add_core
        
    # This method removes CIDR rules specified by the given
    # objects containing IP information. It returns an array
    # of removed CIDR rules.
    # 
    # Make sure you will specify correct and exact netmasks
    # in order to delete proper rules. This method will NOT
    # remove rules that imprecisely match given address or rules
    # that logically depends on specified rules, e.g.
    # removing +192.168.0.0/16+ will leave +192.168.0.0/24+
    # untouched. To create access exceptions for some
    # ranges and/or addresses whitelist them using permit
    # method. This method removes rules matching exact addresses/masks.
    #
    # If the first or last argument is a symbol and it's +:white+
    # or +:black+ then the specified rule will be removed
    # only from the given (white or black) list. If the list is
    # not specified the rule will be removed from both lists.
    # 
    # Special case: some CIDR objects may carry information about
    # access list they should belong to. If the last argument
    # of this method does not specify access list and added rule
    # is the kind of special CIDR containing information about
    # assignment to some list then this extra sugar will be used
    # while removing. These special CIDR objects are usualy result
    # of passing IPAccess::List as an argument. To be sure, whichaccess
    # list will be altered always give its name when passing
    # IPAccess::List.
    # 
    # You should avoid passing hostnames as arguments since
    # DNS is not reliable and responses may change with time,
    # which may cause security flaws.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def delete!(*addresses, &block)
      acl_list = nil
      acl_list = addresses.shift if (addresses.first.is_a?(Symbol) && (addresses.first == :white || addresses.first == :black))
      acl_list = addresses.pop if (addresses.last.is_a?(Symbol) && (addresses.last == :white || addresses.last == :black))
      removed = []
      return removed if (addresses.empty? || empty?)
      addrs = IPAccess.to_cidrs(*addresses)
      addrs.each do |addr|
        addr = addr.ipv4 if addr.ipv4_compliant?
        exists = find_me(addr)
        unless exists.nil?
          src_list  = acl_list.nil? ? addr.tag[:ACL] : acl_list
          src_list  = nil if src_list == :grey
          ex_list   = exists.tag[:ACL]
          parent    = exists.tag[:Parent]
          children  = exists.tag[:Subnets]
          if (!src_list.nil? && ex_list == :grey)
            removed.push exists.safe_dup(:Subnets, :Parent)
            if src_list == :black
              exists.tag[:ACL] = :white
              exists.tag.delete(:Reason_black)
            else
              exists.tag[:ACL] = :black
              exists.tag.delete(:Reason_white)
            end
            #exists.tag[:ACL] = (src_list == :black) ? :white : :black
          elsif (src_list.nil? || ex_list == src_list)
            removed.push exists.safe_dup(:Subnets, :Parent)
            exists.tag.delete(:Reason_white) # help garbage collector a bit
            exists.tag.delete(:Reason_black)
            exists.tag.delete(:ACL)
            exists.tag.delete(:Originator)
            parent.tag[:Subnets].delete(exists)
            children.each { |childaddr| add_to_parent(childaddr, parent) }
          end
        end # if found
      end # addresses.each
      @bus.call(&block) unless removed.empty?
      return removed
    end
    
    alias_method :del!, :delete!
    alias_method :delete, :delete!
    
    # Adds IP addresses in given object(s) to white list if called
    # with at least one argument. Returns white list if called
    # without arguments (array of CIDR objects).
    #
    # You should avoid passing hostnames as arguments since
    # DNS is not reliable and responses may change with time,
    # which may cause security flaws.
    
    def whitelist(*addresses)
      addresses.empty? ? self.to_a(:white) : add!(:white, *addresses)
    end
    
    alias_method :add_white,  :whitelist
    alias_method :allow,      :whitelist
    alias_method :permit,     :whitelist
    
    # This works the same way as whitelist but allows you to
    # store a reason.

    def whitelist_reasonable(reason, *addresses)
      addresses.empty? ? self.to_a(:white) : add_reasonable!(reason, :white, *addresses)
    end
    
    # This method removes IP address(-es) from whitelist
    # by calling delete! on it. It returns the
    # result of delete!
    
    def unwhitelist(*addresses)
      self.delete!(:white, *addresses)
    end
    
    alias_method :unwhite,    :unwhitelist
    alias_method :del_white,  :unwhitelist
    alias_method :unallow,    :unwhitelist
    alias_method :unpermit,   :unwhitelist
    
    # Adds IP addresses from given object(s) to black list if called
    # with at least one argument. Returns black list if called
    # without arguments (array of CIDR objects).
    #
    # You should avoid passing hostnames as arguments since
    # DNS is not reliable and responses may change with time,
    # which may cause security flaws.
    
    def blacklist(*addresses)
      addresses.empty? ? self.to_a(:black) : add!(:black, *addresses)
    end
    
    alias_method :add_black,  :blacklist
    alias_method :deny,       :blacklist
    alias_method :block,      :blacklist
    
    # This works the same way as blacklist but allows
    # you to store a reason.
    
    def blacklist_reasonable(reason, *addresses)
      addresses.empty? ? self.to_a(:black) : add_reasonable!(reason, :black, *addresses)
    end
    
    # This method removes IP address(-es) from blacklist
    # by calling delete! on it. It returns the
    # result of delete!
    
    def unblacklist(*addresses)
      self.delete!(:black, *addresses)
    end
    
    alias_method :unblack,    :unblacklist
    alias_method :undeny,     :unblacklist
    alias_method :unblock,    :unblacklist
    alias_method :del_black,  :unblacklist
    
    # This method returns an array of matching CIDR objects
    # for the given objects containing IP information.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use IPAccess::List#granted and IPAccess::List#denied methods.
    #
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    #
    # Examples:
    #     access = IPAccess::List.new '127.0.0.1/8' # blacklisted local IP
    #     access.included '127.0.0.1'               # returns [127.0.0.0/8]
    #     access.included '127.0.0.1/24'            # returns [127.0.0.0/8]
    #     access.included '127.0.0.1'/8             # returns [127.0.0.0/8]
    #     access.included '127.0.1.2'/8             # returns [127.0.0.0/8]
    
    def included(*addresses)
      found = []
      return found if empty?
      addrs = IPAccess.to_cidrs(*addresses)
      return found if addrs.empty?
      addrs.each do |addr|
        rule = included_cidr(addr)
        found.push(rule) unless rule.nil?
      end
      return found
    end
    
    # This method returns +true+ if ALL
    # of the given objects containing IP information
    # match some rules. Otherwise it returns +false+.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use IPAccess::List#granted and IPAccess::List#denied methods.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def include?(*addresses)
      return false if empty?
      addrs = IPAccess.to_cidrs(*addresses)
      return false if addrs.empty?
      addrs.each do |addr|
        rule = included_cidr(addr)
        return false if rule.nil?
      end
      return true
    end
    
    alias_method :include_all?, :include?
    
    # This method returns first matching CIDR rule from
    # the given objects containing IP information.
    # Otherwise it returns +nil+.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use IPAccess::List#granted and IPAccess::List#denied methods.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def included_first(*addresses)
      return nil if empty?
      addrs = IPAccess.to_cidrs(*addresses)
      return nil if addrs.empty?
      addrs.each do |addr|
        rule = included_cidr(addr)
        return rule unless rule.nil?
      end
      return nil
    end
    
    # This method returns +true+ if at least one of
    # the given objects containing IP information
    # matches rule from the list. Otherwise it returns +false+.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use IPAccess::List#granted and IPAccess::List#denied methods.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def include_one?(*addresses)
      not included_first.nil?
    end
    
    # This method returns matching CIDR rule if the given IP address
    # (expressed as CIDR object) is on the list. Otherwise it returns +nil+.
    
    def included_cidr(addr)
      addr = addr.ipv4 if addr.ipv4_compliant?
      root = addr.version == 4 ? @v4_root : @v6_root
      return nil if root.tag[:Subnets].empty?
      found = nil
      found = find_me(addr)
      found = find_parent(addr) if found.nil?
      return nil if (found.nil? || found.hash == root.hash || !found.matches?(addr))
      return found.safe_dup(:Subnets, :Parent)
    end
    
    # This method returns +true+ if the given IP address
    # (expressed as CIDR object) matches some rule.
    # Otherwise it returns +false+.
    #
    # It is designed to browse rules, NOT to check access. To do access
    # check use granted_cidr and denied_cidr methods.
    
    def include_cidr?(addr)
      not included_cidr(addr).nil?
    end
    
    # This method returns an array containing CDIR objects that
    # are result of finding IP rules given in the array.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use granted_cidr and denied_cidr methods.
    # 
    # You should avoid passing hostnames as arguments since
    # DNS is not reliable and responses may change with time,
    # which may cause security flaws.
    
    def rule_exists(list, *addresses)
      found = []
      return found if empty?
      addrs = IPAccess.to_cidrs(*addresses)
      return found if addrs.empty?
      addrs.each do |addr|
        rule = rule_exists_cidr(list, addr)
        found.push(rule) unless rule.nil?
      end
      return found
    end
    private :rule_exists
    
    # This method returns CDIR object that
    # equals given IP rule in the given list.
    # It returns +nil+ if such rule doesn't
    # exists.
    # 
    # It is designed to check rules, NOT access. To do access
    # check use granted_cidr and denied_cidr methods.
    
    def rule_exists_cidr(list, addr)
      addr = addr.ipv4 if addr.ipv4_compliant?
      root = addr.version == 4 ? @v4_root : @v6_root
      return nil if root.tag[:Subnets].empty?
      found = find_me(addr)
      if (found.nil? || found.hash == root.hash ||
          (found.tag[:ACL] != list && found.tag[:ACL] != :grey))
        return nil
      else
        return found.safe_dup(:Subnets, :Parent)
      end
    end
    private :rule_exists_cidr
    
    # This method returns an array containing CDIR objects that
    # are result of finding given IP rules in the black list.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use IPAccess::List#granted and IPAccess::List#denied methods.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def find_blacklist_rules(*addresses)
      rule_exists(:black, *addresses)
    end
    
    alias_method :find_blacklist_rule, :find_blacklist_rules
    
    # This method returns CDIR object that
    # equals given IP rule in the black list.
    # Otherwise it returns +nil+.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use granted_cidr and denied_cidr methods.
    
    def find_blacklist_rule_cidr(addr)
      rule_exists_cidr(:black, addr)
    end
    
    # This method returns +true+ if ALL of the given
    # IP addresses/masks are present in the black list.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use IPAccess::List#granted and IPAccess::List#denied methods.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def blacklist_rules_exist?(*addresses)
      addrs = IPAccess.to_cidrs(*addresses)
      return found if addrs.empty?
      addrs.each do |addr|
        rule = rule_exists_cidr(:black, addr)
        return false if rule.nil?
      end
      return true
    end
    
    alias_method :blacklist_rule_exists?, :blacklist_rules_exist?
    
    # This method returns +true+ if the given
    # IP address is on the IP rules black list.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use IPAccess::List#granted and IPAccess::List#denied methods.
      
    def blacklist_rule_exists_cidr?(addr)
      not rule_exists_cidr(:black, addr).nil?
    end
    
    # This method returns an array containing CDIR objects that
    # is result of finding given IP rules in the white list.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use IPAccess::List#granted and IPAccess::List#denied methods.
    #
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def find_whitelist_rules(*addresses)
      rule_exists(:white, *addresses)
    end
    
    alias_method :find_blacklist_rule, :find_blacklist_rules
    
    # This method returns CDIR object that
    # equals given IP rule in the white list.
    # 
    # It is designed to check rules, NOT access. To do access
    # check use allowed_cidr and denied_cidr methods.
    
    def find_whitelist_rule_cidr(addr)
      rule_exists_cidr(:white, addr)
    end
    
    # This method returns +true+ if ALL of the given
    # IP addresses are on the white list.
    # 
    # It is designed to check rules, NOT access. To do access
    # check use allowed and denied methods.
    #
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def whitelist_rules_exist?(*addresses)
      addrs = IPAccess.to_cidrs(*addresses)
      return found if addrs.empty?
      addrs.each do |addr|
        rule = rule_exists_cidr(:white, addr)
        return false if rule.nil?
      end
      return true
    end
    
    # This method returns +true+ if the given
    # IP address is on the IP rules white list.
    # 
    # It is designed to check rules, NOT access. To do access
    # check use allowed and denied methods.
    
    def whitelist_rule_exists_cidr?(addr)
      not rule_exists_cidr(:white, addr).nil?
    end
    
    # This method returns CIDR rule that is the same
    # as given IP and mask. It returns copy
    # of a rule that query matches (CIDR object) or +nil+
    # if no match was found.
    #
    # Examples:
    #     access = IPAccess::List.new '127.0.0.1/8'   # blacklisted local IP
    #     access.find '127.0.0.1'                   # returns nil
    #     access.find '127.0.0.1/24'                # returns nil
    #     access.find '127.0.0.1'/8                 # returns CIDR: 127.0.0.0/8
    #     access.find '127.0.1.2'/8                 # returns CIDR: 127.0.0.0/8
    # 
    # If you want simpler or more fancy search in rules
    # (e.g. without need to specify mask or with ability to
    # check many rules at one time) use methods like
    # find_blacklist_rules or find_whitelist_rules.
    # 
    # It is designed to browse rules, NOT to check access. To do access
    # check use IPAccess::List#granted and IPAccess::List#denied methods.
    # 
    # See IPAccess.to_cidrs description for more info about argument
    # you may pass to it. Be aware that in case of name or special
    # symbol given as an address only first result will be used and
    # it will probably do not match because lack of proper netmask.
    
    def find(addr)
      return nil if empty?
      addr = IPAccess.to_cidr(addr)
      return nil if addr.nil?
      addr = addr.ipv4 if addr.ipv4_compliant?
      root = addr.version == 4 ? @v4_root : @v6_root
      return nil if root.tag[:Subnets].empty?
      return super(addr)
    end
    
    # This method should be used to check whether access
    # is denied for the IP given as argument. It is
    # recommended to use it in low-level routines. 
    # 
    # This method returns a hash containing pair of CIDR objects.
    # First, indexed as +:IP+, contains an IP address.
    # Second, indexed as +:Rule+, contains matching rule.
    # Matching means that IP is blacklisted and is not
    # whitelisted.
    # 
    # If there is no match it returns an empty hash.
    # 
    # To not create copy of object when reporting rule
    # but to use reference to original entry you may set
    # second argument to +true+. Use this with caution since
    # modifying returned object may affect internal
    # structure of access list.
    
    def denied_cidr(addr, nodup=false)
      addr = addr.ipv4 if addr.ipv4_compliant?
      root = addr.version == 4 ? @v4_root : @v6_root
      list = root
      ret = {}
      return ret if list.tag[:Subnets].length.zero?
      
      until (li = NetAddr.cidr_find_in_list(addr, list.tag[:Subnets])).nil?
        if li.is_a?(Integer)
          li = list.tag[:Subnets][li]
          break
        else
          if li.tag[:ACL] == :black
            list = li
          else
            break
          end
        end
      end
      
      li = list if li.nil?
      if (!li.nil? && li.tag[:ACL] == :black && li.matches?(addr))
        if nodup
          rule = li
          addr = addr
        else
          rule = li.safe_dup(:Subnets, :Parent)
          addr = addr.safe_dup
        end
        ret[:IP] = addr
        ret[:Rule] = rule
      end
      return ret
    end
    
    # This method returns +true+ if the given CIDR contains
    # blacklisted and not whitelisted address. Otherwise
    # it returns +false+.
    # 
    # It should be used to check access for one IP. It is recommended
    # to use it in low-level routines.
    
    def denied_cidr?(addr)
      not denied_cidr(addr, true).empty?
    end
    
    # This method checks if access for IP or IPs is denied.
    # It returns an array of hashes containing tested CIDR
    # objects (named +:IP+) and rules objects (named +:Rule+).
    # This pair is present in returned hash if given IP address matches
    # black list rules and noesn't match white list rules.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    #
    # It should be used to check access for many IP addresses
    # and/or address(-es) that are not necessarily represented
    # by CIDR objects.
    # 
    # You should avoid passing hostnames as arguments since
    # DNS is not reliable and responses may change with time,
    # which may cause security flaws.
    #
    # To not create copy of objects when reporting rules
    # but to use reference to original entries you may set
    # last argument +true+. Use this with caution since
    # modifying returned object may affect internal
    # structure of access list.
    
    def denied(*addresses)
      found = []
      return found if empty?
      nodup = addresses.last.is_a?(TrueClass) ? addresses.pop : false
      addrs = IPAccess.to_cidrs(*addresses)
      addrs.each do |addr|
        pair = denied_cidr(addr, nodup)
        found.push(pair) unless pair.empty?
      end
      return found
    end
    
    # This method returns +true+ if at least one of given CIDR
    # objects matches black list rules and doesn't match white
    # list rules. Otherwise it returns +false+.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def denied?(*addresses)
      addresses.push true
      not denied(*addresses).empty?
    end
    
    alias_method :denied_one?,     :denied?
    alias_method :denied_one_of?,  :denied?
    
    # This method returns given CIDR object
    # if the given CIDR is not blacklisted or is whitelisted.
    # Otherwise it returns +nil+.
    #
    # It should be used to check access for one IP. It is recommended
    # to use it in low-level routines.
    
    def granted_cidr(addr)
      denied_cidr(addr, true).empty? ? addr : nil
    end
    
    # This method returns +true+ if the given CIDR is not
    # blacklisted or is whitelisted. Otherwise it returns +false+.
    # 
    # It should be used to check access for one IP. It is
    # recommended to use it in low-level routines.
    
    def granted_cidr?(addr)
      denied_cidr(addr, true).empty?
    end
    
    # This method returns an array of the given CIDR objects that
    # don't match black list rules or match white list rules.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    #
    # It should be used to check access for many IP addresses
    # and/or address(-es) that are not necessarily represented
    # by CIDR objects.
    #
    # If the symbol +:include_origin+ is present as one of
    # the given arguments then underlying, resolving method
    # will attach each original, passed in object to corresponding
    # NetAddr::CIDR used while checking. These objects may be
    # accessed using <tt>tag[:Originator]</tt> called on each resulting
    # object.
    #
    # You should avoid passing hostnames as arguments since
    # DNS is not reliable and responses may change with time,
    # which may cause security flaws.
      
    def granted(*addresses)
      found = []
      return found if empty?
      addresses = IPAccess.to_cidrs(*addresses)
      addresses.each do |addr|
        rule = denied_cidr(addr, true)
        found.push(addr) if rule.empty?
      end
      return found
    end
    
    # This method returns +true+ if all of given CIDR
    # objects are not blacklisted or are whitelisted.
    # Otherwise it returns +false+.
    # 
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    # 
    # If the symbol +:include_origin+ is present as one of
    # the given arguments then underlying, resolving method
    # will attach each original, passed in object to corresponding
    # NetAddr::CIDR used while checking. These objects may be
    # accessed using <tt>tag[:Originator]</tt> called on each resulting
    # object.
    # 
    # You should avoid passing hostnames as arguments since
    # DNS is not reliable and responses may change with time,
    # which may cause security flaws.
    
    def granted?(*addresses)
      addresses.push true
      denied(*addresses).empty?
    end
    
    alias_method :granted_one?,     :granted?
    alias_method :granted_one_of?,  :granted?
    
    # Returns new instance containing elements from this object
    # and objects passed as an argument. If objects contain IP
    # information but it's impossible to obtain whether they
    # relate to black or white list, then blacklisting is assumed.
    #
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def +(*addresses)
      obj = self.class.new(self)
      obj.add!(*addresses)
      return obj
    end
    
    # Returns new list with removed CIDR objects which are exactly
    # the same as objects passed as an argument. The original
    # object is not changed.
    #
    # See IPAccess.to_cidrs description for more info about arguments
    # you may pass to it.
    
    def -(*addresses)
      self_copy = self.class.new(self)
      self_copy.delete(*addresses)
      return self_copy
    end
    
    # Returns list of addresses and masks as a string with
    # elements joined using space or given string.
    
    def join(sep=' ')
      dump.map do |obj|
        obj[:CIDR].to_s
      end.join(sep)
    end
    
    # Remove all elements.
    
    def clear!
      remove!('0.0.0.0/0')
      remove!('::/0')
    end
    
    # This method returns +true+ if the list is empty.
    
    def empty?
      @v4_root.tag[:Subnets].empty? &&
      @v6_root.tag[:Subnets].empty?
    end
    
    # This operator calls add! method.
    
    def <<(*addresses)
      add!(*addresses)
      return self
    end
    
    # This method returns an array of CIDR objects belonging
    # to given access list. If no list is specified it returns
    # an array containing all lists. It preserves access list
    # information in copied objects.
    
    def dump_flat_list(parent, type=nil)
      list = []
      parent.tag[:Subnets].each do |entry|
        if (type.nil? || entry.tag[:ACL] == type || entry.tag[:ACL] == :grey)
          list.push(entry)
        end
        if (entry.tag[:Subnets].length > 0)
          list.concat dump_flat_list(entry, type) 
        end
      end
      list.map { |cidr| cidr.safe_dup(:Subnets, :Parent) }
      return list
    end
    private :dump_flat_list
    
    # This method produces array of CIDR objects that
    # belong to an access list specified by type (:white or :black).
    # If no type is given it returns all entries. It preserves
    # access list assignment information in CIDR copies.
    
    def to_a(type=nil)
      dump_flat_list(@v4_root, type) +
      dump_flat_list(@v6_root, type)
    end
    
    # This method shows internal tree of CIDR objects marked
    # with access list they belong to.
    # 
    # While interpreting it
    # you should be aware that access for tested IP will not
    # be denied if black list rule has at least one whitelisted,
    # preceding rule in the path that leads to it. You may
    # also notice doubled entries sometimes. That happens
    # in case when the same rule is belongs to both:
    # black list and white list.
    #
    # When the argument is set to +true+ it will also
    # print a reasons of adding to lists.
    
    def show(reasons=false)
      list4 = dump_children(@v4_root)
      list6 = dump_children(@v6_root)
      
      printed = "IPv4 Tree\n---------\n" if list4.length.nonzero?
      list4.each do |entry|
        cidr    = entry[:CIDR]
        depth   = entry[:Depth]
        alist   = cidr.tag[:ACL]
        indent  = depth.zero? ? "" : " " * (depth*3)
        space   = " " * (44 - (cidr.desc.length+(depth*3)))
        space   = " " if space.empty?
        if alist == :grey
          printed << "[black] #{indent}#{cidr.desc}#{space}#{cidr.tag[:Reason_black]}\n"
          printed << "[white] #{indent}#{cidr.desc}#{space}#{cidr.tag[:Reason_white]}\n"
        else
          alist   = cidr.tag[:ACL].nil? ? "undef" : cidr.tag[:ACL]
          reason  = cidr.tag[("Reason_" + alist.to_s).to_sym]
          printed << "[#{alist}] #{indent}#{cidr.desc}#{space}#{reason}\n"
        end
      end
      
      printed << "\nIPv6 Tree\n---------\n" if list6.length.nonzero?
      list6.each do |entry|
        cidr    = entry[:CIDR]
        depth   = entry[:Depth]
        alist   = cidr.tag[:ACL]
        desc    = cidr.desc(:Short=>true)
        desc    = "::#{desc}" if desc =~ /^\//
        desc    = ":#{desc}" if desc =~ /^:[^:]/
        indent  = depth.zero? ? "" : " " * (depth*3)
        space   = " " * (44 - (desc.length+(depth*3)))
        space   = " " if space.empty?
        if alist == :grey
          printed << "[black] #{indent}#{desc}#{space}#{cidr.tag[:Reason_black]}\n"
          printed << "[white] #{indent}#{desc}#{space}#{cidr.tag[:Reason_white]}\n"
        else
          alist   = cidr.tag[:ACL].nil? ? "undef" : cidr.tag[:ACL]
          reason  = cidr.tag[("Reason_" + alist.to_s).to_sym]
          printed << "[#{alist}] #{indent}#{desc}#{space}#{reason}\n"
        end
      end
      return printed
    end
  
  end # class IPAccess::List

end # module IPAccess
