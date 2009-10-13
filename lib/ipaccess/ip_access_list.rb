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
require 'ipaccess/patches/netaddr'

module IPAccess

  # This class maintains a simple access list containing two lists of rules.
  # 
  # === Access lists
  # 
  # IPAccess::List objects contain two <b>lists of rules</b>:
  # <b>white list</b> and <b>black list</b>. You can add IP rules
  # (both IPv4 and IPv6) to these lists. *Rules* are IP
  # addresses with netmasks.
  # 
  # === Rules management
  # 
  # The class provides methods for easy administration
  # of lists and makes use of method IPAccess::List.to_cidrs that
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
    
    # Creates new IPAccess::List object. You may pass objects
    # (containing IP information) to it. These objects will
    # create black list rules. See to_cidrs description
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
    
    def initialize(*args)
      args = [] if args == [nil]
      super()
      add!(*args) unless args.empty?
      return self
    end
    
    # This method converts names to NetAddr::CIDR objects. It returns an array of CIDR objects.
    # 
    # Allowed input are strings (DNS names or IP addresses optionally with masks), numbers (IP addresses representation),
    # IPSocket objects, URI objects, IPAddr objects, Net::HTTP objects, IPAddrList objects, NetAddr::CIDR objects,
    # NetAddr::Tree objects, IPAccess::List objects, symbols, objects that contain file descriptors bound to sockets
    # (including OpenSSL sockets) and arrays of these.
    #
    # In case of resolving the IPv6 link-local addresses zone index is removed. In case of DNS names there may
    # occur Resolv::ResolvError exceptions.
    #
    # When an argument called +:include_origins+ is present then the method will attach
    # original converted objects to results as the +:Origin+ tag of CIDR objects (<tt>tag[:Origin]</tt>).
    # This rule applies only to single objects or objects inside of arrays or sets.
    # Objects that are kind of NetAddr::CIDR, IPAccess::Set, NetAddr::Tree and arrays will
    # never be set as originators.
    # 
    # ==== Examples
    # 
    #     to_cidrs("127.0.0.1")                      # uses the IP address
    #     to_cidrs(2130706433)                       # uses numeric representation of 127.0.0.1
    #     to_cidrs(:private, "localhost")            # uses special symbol and DNS hostname
    #     to_cidrs(:private, :localhost)             # uses special symbols
    #     to_cidrs [:private, :auto]                 # other way to write the above
    #     to_cidrs "10.0.0.0/8"                      # uses masked IP address
    #     to_cidrs "10.0.0.0/255.0.0.0"              # uses masked IP address
    #     to_cidrs IPSocket.new("www.pl", 80)        # uses the socket
    #     to_cidrs IPAddr("10.0.0.1")                # uses IPAddr object
    #     to_cidrs NetAddr::CIDR.create("10.0.0.1")  # uses NetAddr object
    #     to_cidrs URI('http://www.pl/')             # uses URI
    #     to_cidrs 'http://www.pl/'                  # uses the extracted host string
    #     to_cidrs 'somehost.xx'                     # uses the host string (fetches ALL addresses from DNS)
    #     to_cidrs 'somehost.xx/16'                  # uses the host string and a netmask
    #
    # ==== Special symbols
    #
    # When symbol is passed to this method it tries to find out if it has special meaning.
    # That allows you to create access rules in an easy way. For most of them you may
    # also specify IP protocol version using +ipv4_+ or +ipv6_+ prefix.
    # 
    # Known symbols are:
    #
    # <b>+:all+</b> (+:any+, +:anyone+, +:world+, +:internet+, +:net+, +:everything+, +:everyone+, +:everybody+, +:anybody+)
    # 
    # variants: +:ipv4_+ and +:ipv6_+
    #
    # Creates masked IP address that matches all networks:
    #     – 0.0.0.0/0
    #     – ::/0
    # 
    # <b>+:broadcast+</b> (+:brd+)
    # 
    # variants: +:ipv4_+ and +:ipv6_+
    #
    # Creates masked IP address that matches generic broadcast address:
    #     – 255.255.255.255/32
    #     – ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128
    #
    # <b>+:local+</b> (+:localhost+, +:localdomain+, +:loopback+, +:lo+)
    # 
    # variants: +:ipv4_+ and +:ipv6_+
    # 
    # Creates masked IP addresses that match localhost:
    #     – 127.0.0.1/8
    #     – ::1/128
    #
    # <b>+:auto+</b> (+:automatic+, +:linklocal+)
    # 
    # variants: +:ipv4_+ and +:ipv6_+
    #  
    # Creates masked IP addresses that match automatically assigned address ranges:
    #     – 169.254.0.0/16
    #     – fe80::/10
    # 
    # <b>+:private+</b> (+:intra+, +:intranet+, +:internal+)
    # 
    # variants: +:ipv4_+ and +:ipv6_+
    #
    # Creates masked IP addresses that match private ranges:
    #     – 10.0.0.0/8
    #     – 172.16.0.0/12
    #     – 192.168.0.0/16
    #     – 2001:10::/28
    #     – 2001:db8::/32
    #     – fc00::/7
    #     – fdde:9e1a:dc85:7374::/64
    # 
    # <b>+:multicast+</b> (+:multi+, +:multiemission+)
    # 
    # variants: +:ipv4_+ and +:ipv6_+
    #
    # Creates masked IP addresses that match multicast addresses ranges:
    #     – 224.0.0.0/4
    #     – ff00::/8
    #     – ff02::1:ff00:0/104
    # 
    # <b>+:reserved+</b> (+:example+)
    # 
    # variants: +:ipv4_+
    # 
    # Creates masked IP addresses that match reserved addresses ranges:
    #     – 192.0.2.0/24
    #     – 128.0.0.0/16
    #     – 191.255.0.0/16
    #     – 192.0.0.0/24
    #     – 198.18.0.0/15
    #     – 223.255.255.0/24
    #     – 240.0.0.0/4
    # 
    # <b>+:strange+</b> (+:unusual+, +:nonpublic+, +:unpublic+)
    #
    # Creates masked IP addressess that match the following sets (both IPv4 and IPv6):
    #     – :local
    #     – :auto
    #     – :private
    #     – :reserved
    #     – :multicast
    
    def self.to_cidrs(*obj)
      obj = obj.flatten
      include_origins = false
      obj.delete_if { |x| include_origins = true if (x.is_a?(Symbol) && x == :include_origins) }
      
      if obj.size == 1
        obj = obj.first
      else
        ary = []
        obj.each do |o|
          ary += include_origins ? to_cidrs(o, :include_origins) : to_cidrs(o)
        end
        ary.flatten!
        return ary
      end
      
      ori_obj = obj
      
      # NetAddr::CIDR - immediate generation
      if obj.is_a?(NetAddr::CIDR)
        r = obj.dup
        r.tag[:Originator] = ori_obj if include_origins
        return [r] 
      end
      
      # IPAccess::List - immediate generation
      return obj.to_a if obj.is_a?(self.class)
    
      # NetAddr::Tree - immediate generation
      return obj.dump.map { |addr| addr[:CIDR] } if obj.is_a?(NetAddr::Tree)
    
      # number - immediate generation
      if obj.is_a?(Numeric)
        r =  NetAddr::CIDR.create(obj)
        r.tag[:Originator] = ori_obj if include_origins
        return [r]
      end
          
      # object containing socket member (e.g. Net::HTTP) - fetch socket
      if obj.respond_to?(:socket)
        obj = obj.socket
      elsif obj.respond_to?(:sock)
        obj = obj.sock
      elsif obj.respond_to?(:client_socket)
        obj = obj.client_socket
      elsif obj.instance_variable_defined?(:@socket)
        obj = obj.instance_variable_get(:@socket)
      elsif obj.instance_variable_defined?(:@client_socket)
        obj = obj.instance_variable_get(:@client_socket)
      elsif obj.instance_variable_defined?(:@sock)
        obj = obj.instance_variable_get(:@sock)
      end
      obj = obj.io if (obj.respond_to?(:io) && obj.io.respond_to?(:getpeername))
      
      # some file descriptor but not socket - fetch socket
      obj = Socket.for_fd(obj.fileno) if (!obj.respond_to?(:getpeername) && obj.respond_to?(:fileno))
      
      # Socket - immediate generation
      if obj.respond_to?(:getpeername)
        peeraddr = Socket.unpack_sockaddr_in(obj.getpeername).last.split('%').first
        r = NetAddr::CIDR.create(peeraddr)
        r.tag[:Originator] = ori_obj if include_origins
        return [r]
      end
      
      # symbol - immediate generation
      r_args = nil
      if obj.is_a?(Symbol)
      case obj
        when :ipv4_all, :ipv4_any, :ipv4_anyone, :ipv4_world, :ipv4_internet, :ipv4_net, :ipv4_everything, :ipv4_everyone, :ipv4_everybody, :ipv4_anybody
          obj = [ "0.0.0.0/0" ]
        when :ipv6_all, :ipv6_any, :ipv6_anyone, :ipv6_world, :ipv6_internet, :ipv6_net, :ipv6_everything, :ipv6_everyone, :ipv6_everybody, :ipv6_anybody
          obj = [ "0.0.0.0/0", "::/0" ]
        when :ipv4_broadcast, :ipv4_brd
          obj = [ "255.255.255.255/32" ]
        when :ipv6_broadcast, :ipv6_brd
          obj = [ "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128" ]
        when :ipv4_local, :ipv4_localhost, :ipv4_loopback, :ipv4_lo
          obj = [ "127.0.0.1/8" ]
        when :ipv6_local, :ipv6_localhost, :ipv6_loopback, :ipv6_lo
          obj = [ "::1/128" ]
        when :ipv4_auto, :ipv4_automatic, :ipv4_linklocal
          obj = [ "169.254.0.0/16" ]
        when :ipv6_auto, :ipv6_automatic, :ipv6_linklocal
          obj = [ "fe80::/10" ]
        when :ipv4_private, :ipv4_intra, :ipv4_intranet, :ipv4_internal
          obj = [ "10.0.0.0/8",
                  "172.16.0.0/12",
                  "192.168.0.0/16" ]
        when :ipv6_private, :ipv6_intra, :ipv6_intranet, :ipv6_internal, :ipv6_ula, :ipv6_unique
          obj = [ "2001:10::/28",
                  "2001:db8::/32",
                  "fc00::/7",
                  "fdde:9e1a:dc85:7374::/64" ]
        when :ipv4_multicast, :ipv4_multi, :ipv4_multiemission
          obj = [ "224.0.0.0/4" ]
        when :ipv6_multicast, :ipv6_multi, :ipv6_multiemission
          obj = [ "ff00::/8",
                  "ff02::1:ff00:0/104" ]
        when :ipv4_example, :ipv4_reserved
          obj = [ "192.0.2.0/24",
                  "128.0.0.0/16",
                  "191.255.0.0/16",
                  "192.0.0.0/24",
                  "198.18.0.0/15",
                  "223.255.255.0/24",
                  "240.0.0.0/4" ]
        when :all, :any, :anyone, :world, :internet, :net, :everything, :everyone, :everybody, :anybody
          r_args = [ :ipv4_all,
                     :ipv6_all ] 
        when :broadcast, :brd
          r_args = [ :ipv4_broadcast,
                     :ipv6_broadcast ]
        when :local, :localhost, :localdomain, :loopback, :lo
          r_args = [ :ipv4_local,
                     :ipv6_local ]
        when :auto, :automatic, :linklocal
          r_args = [ :ipv4_auto,
                     :ipv6_auto ]            
        when :private, :intra, :intranet, :internal
          r_args = [ :ipv4_private,
                     :ipv6_private ]
        when :multicast, :multi, :multiemission
          r_args = [ :ipv4_multicast,
                     :ipv6_multicast ]
        when :reserved, :example
          r_args = [ :ipv4_example ]
        when :strange, :unusual, :nonpublic, :unpublic
          r_args = [ :local,
                     :auto,
                     :private,
                     :reserved,
                     :multicast ]
        else
          raise ArgumentError, "provided symbol is unknown: #{obj.to_s}"
        end
        
        unless r_args.nil?
          r_args.push :include_origins if include_origins
          return to_cidrs(*r_args)
        end
        
        # strange types here
        if obj.is_a?(Array)
          return obj.map do |addr|
            r = NetAddr::CIDR.create(addr)
            r.tag[:Originator] = addr if include_origins
            r
          end
        end
      end
      
      # URI or something that responds to host method - fetch string
      obj = obj.host if obj.respond_to?(:host)
      
      # objects of external classes 
      case obj.class.name.to_sym
      when :IPAddr                                          # IPAddr - fetch IP/mask string
        obj = obj.native.inspect.split[1].chomp('>')[5..-1]
      when :IPAddrList                                      # IPAddrList - pass array to parse
        return include_origins ? to_cidrs(obj.to_a, :include_origins) : to_cidrs(obj.to_a)
      end
      
      # string or similar - immediate generation
      if obj.respond_to?(:to_s)
        hostmask = ""
        obj = obj.to_s
        # URI
        if obj =~ /^[^:]+:\/\/(.*)/
          obj = $1.split('/').first
          # IP in URI
          if obj =~ /^\[([^\]]+)\]/
            obj = $1
          else
            obj = obj.split(':').first
          end
        # host(s) and a mask
        elsif obj =~ /^([^\/]+)(\/((\d{1,2}$)|(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$)))/
          obj = $1
          hostmask = $2
        end
        begin
          ipa = obj.split('%').first.to_s
          r = NetAddr::CIDR.create(ipa + hostmask)
        rescue NetAddr::ValidationError
          begin
            addresses = Resolv::getaddresses(obj)
          rescue NoMethodError # unhandled error
            raise Resolv::ResolvError, "not connected"
          end
          addresses.map! do |addr|
            begin
              r = NetAddr::CIDR.create(addr.split('%').first + hostmask)
              r.tag[:Originator] = ori_obj
              r
            rescue ArgumentError
              nil
            end
          end
          addresses.flatten!
          addresses.compact!
          return addresses
        end
        r.tag[:Originator] = ori_obj
        return r
      end
      
      # should never happend
      r = obj.is_a?(NetAddr::CIDR) ? obj.dup : NetAddr::CIDR.create(obj.to_s)
      r.tag[:Originator] = ori_obj
      return r
    end
    
    # This method calls IPAccess::List.to_cidrs
    
    def to_cidrs(*args)
      self.class.to_cidrs(*args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def grep(*args)
      return [] if empty?
      out_ary = []
      addrs = to_cidrs(*args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def grep_exact(*args)
      return [] if empty?
      out_ary = []
      addrs = to_cidrs(*args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def add!(*args)
      acl_list = nil
      acl_list = args.shift if (args.first.is_a?(Symbol) && (args.first == :white || args.first == :black))
      acl_list = args.pop if (args.last.is_a?(Symbol) && (args.last == :white || args.last == :black))
      return nil if args.empty?
      addrs = to_cidrs(*args)
      addrs.each do |addr|
        addr = addr.ipv4 if addr.ipv4_compliant?
        add_list = acl_list.nil? ? addr.tag[:ACL] : acl_list  # object with extra sugar
        add_list = :black if add_list.nil?
        exists = find_me(addr)
        if exists.nil?
          addr.tag[:Subnets] = []
          addr.tag[:ACL] = add_list
          add_to_tree(addr)
        elsif exists.tag[:ACL] != add_list
          exists.tag[:ACL] = :ashen
        end
      end
      return nil
    end
    
    alias_method :add, :add!
    
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def delete!(*args)
      acl_list = nil
      acl_list = args.shift if (args.first.is_a?(Symbol) && (args.first == :white || args.first == :black))
      acl_list = args.pop if (args.last.is_a?(Symbol) && (args.last == :white || args.last == :black))
      removed = []
      return removed if (args.empty? || empty?)
      addrs = to_cidrs(*args)
      addrs.each do |addr|
        addr = addr.ipv4 if addr.ipv4_compliant?
        exists = find_me(addr)
        unless exists.nil?
          src_list = acl_list.nil? ? addr.tag[:ACL] : acl_list
          src_list = nil if src_list == :ashen
          ex_list = exists.tag[:ACL]
          parent = exists.tag[:Parent]
          children = exists.tag[:Subnets]
          if (!src_list.nil? && ex_list == :ashen)
            removed.push exists.safe_dup(:Subnets, :Parent)
            exists.tag[:ACL] = (src_list == :black) ? :white : :black
          elsif (src_list.nil? || ex_list == src_list)
            removed.push exists.safe_dup(:Subnets, :Parent)
            parent.tag[:Subnets].delete(exists)
            children.each { |childaddr| add_to_parent(childaddr, parent) }
          end
        end # if found
      end # args.each
      
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
    
    def whitelist(*args)
      args.empty? ? self.to_a(:white) : add!(:white, *args)
    end
    
    alias_method :add_white,  :whitelist
    alias_method :allow,      :whitelist
    alias_method :permit,     :whitelist
    
    # This method removes IP address(-es) from whitelist
    # by calling delete! on it. It returns the
    # result of delete!
    
    def unwhitelist(*args)
      self.delete!(:white, *args)
    end
    
    alias_method :unwhite,    :unwhitelist
    alias_method :del_white,  :unwhitelist
    alias_method :unallow,    :unwhitelist
    alias_method :unpermit,   :unwhitelist
      
    # Adds IP addresses in given object(s) to black list if called
    # with at least one argument. Returns black list if called
    # without arguments (array of CIDR objects).
    #
    # You should avoid passing hostnames as arguments since
    # DNS is not reliable and responses may change with time,
    # which may cause security flaws.
    
    def blacklist(*args)
      args.empty? ? self.to_a(:black) : add!(:black, *args)
    end
    
    alias_method :add_black,  :blacklist
    alias_method :deny,       :blacklist
    alias_method :block,      :blacklist
    
    # This method removes IP address(-es) from blacklist
    # by calling delete! on it. It returns the
    # result of delete!
    
    def unblacklist(*args)
      self.delete!(:black, *args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    #
    # Examples:
    #     access = IPAccess::List.new '127.0.0.1/8'   # blacklisted local IP
    #     access.included '127.0.0.1'               # returns [127.0.0.0/8]
    #     access.included '127.0.0.1/24'            # returns [127.0.0.0/8]
    #     access.included '127.0.0.1'/8             # returns [127.0.0.0/8]
    #     access.included '127.0.1.2'/8             # returns [127.0.0.0/8]
    
    def included(*args)
      found = []
      return found if empty?
      addrs = to_cidrs(*args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def include?(*args)
      return false if empty?
      addrs = to_cidrs(*args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def included_first(*args)
      return nil if empty?
      addrs = to_cidrs(*args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def include_one?(*args)
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
    
    def rule_exists(list, *args)
      found = []
      return found if empty?
      addrs = to_cidrs(*args)
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
          (found.tag[:ACL] != list && found.tag[:ACL] != :ashen))
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def find_blacklist_rules(*args)
      rule_exists(:black, *args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def blacklist_rules_exist?(*args)
      addrs = to_cidrs(*args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def find_whitelist_rules(*args)
      rule_exists(:white, *args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def whitelist_rules_exist?(*args)
      addrs = to_cidrs(*args)
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
    # See to_cidrs description for more info about argument
    # you may pass to it. Be aware that in case of name or special
    # symbol given as an address only first result will be used and
    # it will probably do not match because lack of proper netmask.
      
    def find(addr)
      return nil if empty?
      addr = to_cidrs(addr)
      return nil if addr.empty?
      addr = addr.first
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
      return nil if list.tag[:Subnets].length.zero?
      
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
      
      ret = {}
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
    # See to_cidrs description for more info about arguments
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
    
    def denied(*args)
      found = []
      return found if empty?
      nodup = args.last.is_a?(TrueClass) ? args.pop : false
      addrs = to_cidrs(*args)
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
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def denied?(*args)
      args.push true
      not denied(*args).empty?
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
    # See to_cidrs description for more info about arguments
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
      
    def granted(*args)
      found = []
      return found if empty?
      args = to_cidrs(*args)
      args.each do |addr|
        rule = denied_cidr(addr, true)
        found.push(addr) if rule.empty?
      end
      return found
    end
    
    # This method returns +true+ if all of given CIDR
    # objects are not blacklisted or are whitelisted.
    # Otherwise it returns +false+.
    # 
    # See to_cidrs description for more info about arguments
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
    
    def granted?(*args)
      args.push true
      denied(*args).empty?
    end
    
    alias_method :granted_one?,     :granted?
    alias_method :granted_one_of?,  :granted?
    
    # Returns new instance containing elements from this object
    # and objects passed as an argument. If objects contain IP
    # information but it's impossible to obtain whether they
    # relate to black or white list, then blacklisting is assumed.
    #
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def +(*args)
      obj = self.class.new(self)
      obj.add!(*args)
      return obj
    end
    
    # Returns new list with removed CIDR objects which are exactly
    # the same as objects passed as an argument. The original
    # object is not changed.
    #
    # See to_cidrs description for more info about arguments
    # you may pass to it.
    
    def -(*args)
      self_copy = self.class.new(self)
      self_copy.delete(*args)
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
    
    def <<(*args)
      add!(*args)
      return self
    end
    
    # This method returns an array of CIDR objects belonging
    # to given access list. If no list is specified it returns
    # an array containing all lists. It preserves access list
    # information in copied objects.
    
    def dump_flat_list(parent, type=nil)
      list = []
      parent.tag[:Subnets].each do |entry|
        if (type.nil? || entry.tag[:ACL] == type || entry.tag[:ACL] == :ashen)
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
    # with access list they belong to. While interpreting it
    # you should be aware that access for tested IP will not
    # be denied if black list rule has at least one whitelisted,
    # preceding rule in the path that leads to it. You may
    # also notice doubled entries sometimes. That happens
    # in case when the same rule is belongs to both:
    # black list and white list.
    
    def show()
      list4 = dump_children(@v4_root)
      list6 = dump_children(@v6_root)
    
      printed = "IPv4 Tree\n---------\n" if list4.length.nonzero?
      list4.each do |entry|
        cidr    = entry[:CIDR]
        depth   = entry[:Depth]
        alist   = cidr.tag[:ACL]
        indent  = depth.zero? ? "" : " " * (depth*3)
        if alist == :ashen
          printed << "[black] #{indent}#{cidr.desc}\n"
          printed << "[white] #{indent}#{cidr.desc}\n"
        else
          alist   = cidr.tag[:ACL].nil? ? "[undef]" : "[#{cidr.tag[:ACL]}]" 
          printed << "#{alist} #{indent}#{cidr.desc}\n"
        end
      end
      
      printed << "\nIPv6 Tree\n---------\n" if list6.length.nonzero?
      list6.each do |entry|
        cidr    = entry[:CIDR]
        depth   = entry[:Depth]
        alist   = cidr.tag[:ACL]
        indent  = depth.zero? ? "" : " " * (depth*3)
        if alist == :ashen
          printed << "[black] #{indent}#{cidr.desc(:Short => true)}\n"
          printed << "[white] #{indent}#{cidr.desc(:Short => true)}\n"
        else
          alist   = cidr.tag[:ACL].nil? ? "[undef]" : "[#{cidr.tag[:ACL]}]" 
          printed << "#{alist} #{indent}#{cidr.desc(:Short => true)}\n"
        end
      end
      return printed
    end
  
  end # class IPAccess::List

end # module IPAccess
