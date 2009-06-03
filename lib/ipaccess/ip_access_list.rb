# encoding: utf-8
# 
# Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This is licensed under LGPL or Ruby License.
# 
# === ip_access_list
# 
# This file contains IPAccessList class, which uses
# NetAddr::Tree to implement IP access list.

require 'ipaddr'
require 'socket'
require 'resolv'
require 'netaddr'
require 'ipaccess/netaddr_patch'

# This class implements easy to
# manage IP access list based on NetAddr::Tree
# which uses binary search to speed up
# matching process. It stores data in a tree
# of NetAddr::CIDR objects and allows to add,
# remove and search them.
# 
# ==== Access lists
# 
# To control access IPAccessList maintaines
# two abstract lists: white list and black
# list. Each list contains rules (CIDR objects
# with information about IP address and
# network mask). Access is evaluated as
# blocked when tested IP address matches
# rule from black list and not matches any rule
# from white list. Basically, white list rules
# override black list rules.
# 
# To be precise: in order to increase
# lookups performance internally there
# are no real lists but one tree containing
# specially marked objects.
# 
# ==== Basic Operations
# 
# This class has no methods that actualy
# do network operations, it just allows
# you to check IP against black and
# white list. There are 2 major types
# of operations you can perform: rules
# management and access checks.
# 
# Rules management methods allow you to
# add, remove and find IP access rules.
# Access checks let you test if given
# address or addresses are allowed or
# denied to perform network operations
# according to rules.
#
# ==== IPv4 and IPv6
# 
# IPv6 addresses that are IPv4 compatible
# or IPv4 masked are automatically
# translated into IPv4 addresses while
# adding or searching.
#
# ==== Examples
# 
# Examples of usage:
#
#     access = IPAccessList.new       # create new access list
#     access.blacklist :ipv4_private  # blacklist private IPv4 addresses
#     access.whitelist '172.16.0.7'   # whitelist 172.16.0.7
#     access.granted? '172.16.0.7'    # check access
#     access.granted? '172.16.0.1'    # check access
#
# Examples of deny-all & allow-selected strategy:
# 
#     access = IPAccessList.new       # create new access list
#     access.deny :all                # blacklist all
#     access.allow '192.168.1.0/24'   # allow my private network
#     access.allow :local             # allow localhost
#     
#     puts access.show                # display internal structure
#     puts access.blacklist           # display blacklisted IP addresses
#     puts access.whitelist           # display whitelisted IP addresses

class IPAccessList < NetAddr::Tree

  # Creates new IPAccessList object. You may pass objects
  # containing IP information to it. These objects will
  # create black list rules. See obj_to_cidr description
  # for more info on how to pass arguments.
  #
  # IPAccessList object and/or NetAddr::CIDR object(s) may
  # carry black or white list assignments inside. If such
  # object(s) will be used to create initial ruleset then
  # assignment found there would be used instead of default. 
  #
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time.
  # That may cause security flaws.
  # 
  # Examples:
  #     
  #     IPAccessList.new '192.168.0.0/16', '127.0.0.1/255.0.0.0'
  #     IPAccessList.new :private, :local
  #     IPAccessList.new "randomseed.pl", :nonpublic
  
  def initialize(*args)
    args = [] if args == [nil]
    super()
    add!(args) unless args.empty?
    return self
  end
  
  # This method converts names to NetAddr::CIDR objects. It returns an array of CIDR objects.
  # 
  # Allowed input: string(s) (DNS names or IP addresses optionally with masks), number(s) (IP address representation),
  # IPSocket object(s), URI object(s), IPAddr object(s), Net::HTTP object(s), IPAddrList object(s), NetAddr::CIDR object(s),
  # NetAddr::Tree object(s), IPAccessList object(s), symbol(s), object(s) that contain file descriptors bound to socket(s),
  # and arrays of these.
  #
  # ==== Examples
  # 
  #     obj_to_cidr("127.0.0.1")                      # uses IP address
  #     obj_to_cidr(2130706433)                       # uses numeric representation of 127.0.0.1
  #     obj_to_cidr(:private, "localhost")            # uses special symbol and DNS hostname
  #     obj_to_cidr(:private, :localhost)             # uses special symbols
  #     obj_to_cidr [:private, :auto]                 # other way to write the above
  #     obj_to_cidr "10.0.0.0/8"                      # uses masked IP address
  #     obj_to_cidr "10.0.0.0/255.0.0.0"              # uses masked IP address
  #     obj_to_cidr IPSocket.new("www.pl", 80)        # uses socket
  #     obj_to_cidr IPAddr("10.0.0.1")                # uses IPAddr object
  #     obj_to_cidr NetAddr::CIDR.create("10.0.0.1")  # uses NetAddr object
  #     obj_to_cidr URI('http://www.pl/')             # uses URI
  #     obj_to_cidr 'http://www.pl/'                  # uses extracted host string
  #
  # ==== Special symbols
  #
  # When symbol is passed to this method it tries to find out if it has special meaning.
  # That allows you to create access rules in an easy way. For most of them you may
  # also specify IP protocol version using +ipv4_+ or +ipv6_+ prefix.
  # 
  # Known symbols are:
  #
  # ===== +:all+
  # Aliases: +:any+, +:anyone+, +:world+, +:internet+, +:net+, +:everything+, +:everyone+, +:everybody+, +:anybody+
  #
  # Subvariants: +:ipv4_+ and +:ipv6_+
  #
  # Creates masked IP address that matches all networks:
  #     – 0.0.0.0/0
  #     – ::/0
  # 
  # ===== +:broadcast+
  # Aliases: +:brd+
  # Subvariants: +:ipv4_+ and +:ipv6_:+
  #
  # Creates masked IP address that matches generic broadcast address:
  #     – 255.255.255.255/32
  #     – ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128
  #
  # ===== +:local+
  # Aliases: +:localhost+, +:localdomain+, +:loopback+, +:lo+
  # 
  # Subvariants: +:ipv4_+ and +:ipv6_+
  # 
  # Creates masked IP addresses that match localhost:
  #     – 127.0.0.1/8
  #     – ::1/128
  #
  # ===== +:auto+
  # Aliases: +:automatic+, +:linklocal+
  # 
  # Subvariants: +:ipv4_+ and +:ipv6_+
  #  
  # Creates masked IP addresses that match automatically assigned address ranges:
  #     – 169.254.0.0/16
  #     – fe80::/10
  # 
  # ===== +:private+
  # Aliases: +:intra+, +:intranet+, +:internal+
  # 
  # Subvariants: +:ipv4_+ and +:ipv6_+
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
  # ===== +:multicast+
  # Aliases: +:multi+, +:multiemission+
  # 
  # Subvariants: +:ipv4_+ and +:ipv6_+
  #
  # Creates masked IP addresses that match multicast addresses ranges:
  #     – 224.0.0.0/4
  #     – ff00::/8
  #     – ff02::1:ff00:0/104
  # 
  # ===== +:reserved+
  # Aliases: +:example+
  # 
  # Subvariants: +:ipv4_+
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
  # ===== +:strange+
  # Aliases: +:unusual+, +:nonpublic+, +:unpublic+
  #
  # Creates masked IP addressess that match the following sets (both IPv4 and IPv6):
  #     – :local
  #     – :auto
  #     – :private
  #     – :reserved
  #     – :multicast
  
  def self.obj_to_cidr(*obj)
    obj = obj.flatten

    if obj.size == 1
      obj = obj.first
    else
      ary = []
      obj.each { |o| ary += obj_to_cidr(o) }
      ary.flatten!
      return ary
    end

    # NetAddr::CIDR - immediate generation
    return [obj.dup] if obj.is_a?(NetAddr::CIDR)
    
    # IPAccessList - immediate generation
    return obj.to_a if obj.is_a?(self.class)

    # NetAddr::Tree - immediate generation
    return obj.dump.map { |addr| addr[:CIDR] } if obj.is_a?(NetAddr::Tree)

    # number - immediate generation
    return [NetAddr::CIDR.create(obj)] if obj.is_a?(Numeric)

    # IPAddr - fetch IP/mask string
    obj = obj.native.inspect.split[1].chomp('>')[5..-1] if obj.is_a?(IPAddr)

    # object containing socket member (e.g. Net::HTTP) - fetch socket
    if obj.respond_to?(:socket)
      obj = obj.socket 
    elsif obj.respond_to?(:client_socket)
      obj = obj.client_socket
    elsif obj.instance_variable_defined?(:@socket)
      obj = obj.instance_variable_get(:@socket)
    end 
    obj = obj.io if (obj.respond_to?(:io) && obj.io.respond_to?(:getpeername))
    
    # some file descriptor but not socket - fetch socket
    obj = Socket.for_fd(obj.fileno) if (!obj.respond_to?(:getpeername) && obj.respond_to?(:fileno))
    
    # Socket - immediate generation
    if obj.respond_to?(:getpeername)
      peeraddr = Socket.unpack_sockaddr_in(obj.getpeername).last
      return [NetAddr::CIDR.create(peeraddr)]
    end
    
    # symbol - immediate generation
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
        return obj_to_cidr(:ipv4_all,
                           :ipv6_all)   
      when :broadcast, :brd
        return obj_to_cidr(:ipv4_broadcast,
                           :ipv6_broadcast)
      when :local, :localhost, :localdomain, :loopback, :lo
        return obj_to_cidr(:ipv4_local,
                           :ipv6_local)
      when :auto, :automatic, :linklocal
        return obj_to_cidr(:ipv4_auto,
                           :ipv6_auto)            
      when :private, :intra, :intranet, :internal
        return obj_to_cidr(:ipv4_private,
                           :ipv6_private)
      when :multicast, :multi, :multiemission
        return obj_to_cidr(:ipv4_multicast,
                           :ipv6_multicast)
      when :reserved, :example
        return obj_to_cidr(:ipv4_example)
      when :strange, :unusual, :nonpublic, :unpublic
        return obj_to_cidr(:local,
                           :auto,
                           :private,
                           :reserved,
                           :multicast)
      else
        raise ArgumentError, "Provided symbol is unknown: #{obj.to_s}"
      end
      return obj.map { |addr| NetAddr::CIDR.create(addr) } if obj.is_a?(Array)
    end
    
    # URI or something that responds to host method - fetch string
    obj = obj.host if obj.respond_to?(:host)
    
    # IPAddrList - immediate generation
    return obj.to_a if obj.class.name.to_sym == :IPAddrList
    
    # string or similar - immediate generation
    if obj.respond_to?(:to_s)
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
      end
      begin
        obj = NetAddr::CIDR.create(obj)
      rescue NetAddr::ValidationError
        addresses = Resolv::getaddresses(obj)
        addresses.map! do |addr|
          begin
            NetAddr::CIDR.create(addr)
          rescue ArgumentError
            nil
          end
        end
        addresses.flatten!
        addresses.compact!
        return addresses
      end
    end
    
    # should never happend
    return obj.is_a?(NetAddr::CIDR) ? [obj.dup] : [NetAddr::CIDR.create(obj.to_s)]
  end
  
  # This method calls IPAccessList.obj_to_cidr
  
  def obj_to_cidr(*args)
    self.class.obj_to_cidr(args)
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
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.

  def grep(*args)
    return [] if empty?
    out_ary = []
    addrs = obj_to_cidr(args)
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
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.

  def grep_exact(*args)
    return [] if empty?
    out_ary = []
    addrs = obj_to_cidr(args)
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
  # Special case: some CIDR objects may carry information about
  # access list they should belong to. If the last argument
  # of this method does not specify access list and added rule
  # is the kind of special CIDR containing information about
  # assignment to some list then this extra sugar will be used
  # in assignment instead of default +:black+. These special
  # CIDR object are usualy result of passing IPAccessList
  # as an argument. To be sure which access
  # list will be altered always give its name when passing
  # IPAccessList.
  # 
  # If the given rule is exact (IP and mask) as pre-existent
  # rule in the same access list then it is not added.
  # 
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def add!(*args)
    acl_list = nil
    acl_list = args.shift if (args.first.is_a?(Symbol) && (args.first == :white || args.first == :black))
    acl_list = args.pop if (args.last.is_a?(Symbol) && (args.last == :white || args.last == :black))
    return nil if args.empty?
    addrs = obj_to_cidr(args)
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
  # of passing IPAccessList as an argument. To be sure which access
  # list will be altered always give its name when passing
  # IPAccessList.
  # 
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def delete!(*args)
    acl_list = nil
    acl_list = args.shift if (args.first.is_a?(Symbol) && (args.first == :white || args.first == :black))
    acl_list = args.pop if (args.last.is_a?(Symbol) && (args.last == :white || args.last == :black))
    removed = []
    return removed if (args.empty? || empty?)
    addrs = obj_to_cidr(args)
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
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
  
  def whitelist(*args)
    args.empty? ? to_a(:white) : add!(args, :white)
  end
  
  alias_method :add_white,  :whitelist
  alias_method :allow,      :whitelist
  alias_method :permit,     :whitelist
  
  # Adds IP addresses in given object(s) to black list if called
  # with at least one argument. Returns black list if called
  # without arguments (array of CIDR objects).
  #
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
  
  def blacklist(*args)
    args.empty? ? to_a(:black) : add!(args, :black)
  end
  
  alias_method :add_black,  :blacklist
  alias_method :deny,       :blacklist
  alias_method :block,      :blacklist
  
  # This method returns an array of matching CIDR objects
  # for the given objects containing IP information.
  # 
  # It is designed to browse rules, NOT to check access. To do access
  # check use IPAccessList#granted and IPAccessList#denied methods.
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  #
  # Examples:
  #     access = IPAccessList.new '127.0.0.1/8'   # blacklisted local IP
  #     access.included '127.0.0.1'               # returns [127.0.0.0/8]
  #     access.included '127.0.0.1/24'            # returns [127.0.0.0/8]
  #     access.included '127.0.0.1'/8             # returns [127.0.0.0/8]
  #     access.included '127.0.1.2'/8             # returns [127.0.0.0/8]
  
  def included(*args)
    found = []
    return found if empty?
    addrs = obj_to_cidr(args)
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
  # check use IPAccessList#granted and IPAccessList#denied methods.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.

  def include?(*args)
    return false if empty?
    addrs = obj_to_cidr(args)
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
  # check use IPAccessList#granted and IPAccessList#denied methods.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def included_first(*args)
    return nil if empty?
    addrs = obj_to_cidr(args)
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
  # check use IPAccessList#granted and IPAccessList#denied methods.
  # 
  # See obj_to_cidr description for more info about arguments
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
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
  
  def rule_exists(list, *args)
    found = []
    return found if empty?
    addrs = obj_to_cidr(args)
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
  # check use IPAccessList#granted and IPAccessList#denied methods.
  # 
  # See obj_to_cidr description for more info about arguments
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
  # check use IPAccessList#granted and IPAccessList#denied methods.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def blacklist_rules_exist?(*args)
    addrs = obj_to_cidr(args)
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
  # check use IPAccessList#granted and IPAccessList#denied methods.
    
  def blacklist_rule_exists_cidr?(addr)
    not rule_exists_cidr(:black, addr).nil?
  end

  # This method returns an array containing CDIR objects that
  # is result of finding given IP rules in the white list.
  # 
  # It is designed to browse rules, NOT to check access. To do access
  # check use IPAccessList#granted and IPAccessList#denied methods.
  #
  # See obj_to_cidr description for more info about arguments
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
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def whitelist_rules_exist?(*args)
    addrs = obj_to_cidr(args)
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
  #     access = IPAccessList.new '127.0.0.1/8'   # blacklisted local IP
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
  # check use IPAccessList#granted and IPAccessList#denied methods.
  # 
  # See obj_to_cidr description for more info about argument
  # you may pass to it. Be aware that in case of name or special
  # symbol given as an address only first result will be used and
  # it will probably do not match because lack of proper netmask.
    
  def find(addr)
    return nil if empty?
    addr = obj_to_cidr(addr)
    return nil if addr.empty?
    addr = addr.first
    addr = addr.ipv4 if addr.ipv4_compliant?
    root = addr.version == 4 ? @v4_root : @v6_root
    return nil if root.tag[:Subnets].empty?
    return super(addr)
  end
  
  # This method returns an array containing CIDR object of
  # given address and CIDR object of the matching rule
  # if the given CIDR contains blacklisted and not whitelisted
  # address. Otherwise it returns +nil+.
  #
  # It should be used to check access for one IP. It is
  # recommended to use it in low-level routines.
  #
  # To not create copy of object when reporting rule
  # but to use reference to original entry you may set
  # second argument +true+. Use this with caution since
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
    
    li = list if li.nil?
    if (!li.nil? && li.tag[:ACL] == :black && li.matches?(addr))
      if nodup
        rule = li
        addr = addr
      else
        rule = li.safe_dup(:Subnets, :Parent)
        addr = addr.safe_dup
      end
      return [addr,rule]
    else
      return nil
    end
  end
  
  # This method returns +true+ if the given CIDR contains
  # blacklisted and not whitelisted address. Otherwise
  # it returns +false+.
  # 
  # It should be used to check access for one IP. It is recommended
  # to use it in low-level routines.
  
  def denied_cidr?(addr)
    not denied_cidr(addr, true).nil?
  end
  
  # This method checks if access for IP or IPs is denied.
  # It returns an array of pairs containing tested CIDR
  # objects and rules objects. Pair is present in output
  # if given IP address matches black list rules and
  # noesn't match white list rules.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  #
  # It should be used to check access for many IP addresses
  # and/or address(-es) that are not necessarily represented
  # by CIDR objects.
  # 
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time
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
    args = obj_to_cidr(args)
    args.each do |addr|
      pair = denied_cidr(addr, nodup)
      found.push(pair) unless pair.nil?
    end
    return found
  end
  
  # This method returns +true+ if at least one of given CIDR
  # objects matches black list rules and doesn't match white
  # list rules. Otherwise it returns +false+.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def denied?(*args)
    not denied(args, true).empty?
  end
  
  alias_method :denied_one?,     :denied?
  alias_method :denied_one_of?,  :denied?
  
  # This method returns given CIDR object
  # if the given CIDR is not blacklisted or whitelisted.
  # Otherwise it returns +nil+.
  #
  # It should be used to check access for one IP. It is recommended
  # to use it in low-level routines.
  
  def granted_cidr(addr)
    denied_cidr(addr, true).nil? ? addr : nil
  end
  
  # This method returns +true+ if the given CIDR is not
  # blacklisted or whitelisted. Otherwise it returns +false+.
  # 
  # It should be used to check access for one IP. It is
  # recommended to use it in low-level routines.
  
  def granted_cidr?(addr)
    denied_cidr(addr, true).nil?
  end
  
  # This method returns an array of the given CIDR objects that
  # don't match black list rules or match white list rules.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  #
  # It should be used to check access for many IP addresses
  # and/or address(-es) that are not necessarily represented
  # by CIDR objects.
  #
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
    
  def granted(*args)
    found = []
    return found if empty?
    args = obj_to_cidr(args)
    args.each do |addr|
      rule = denied_cidr(addr, true)
      found.push(addr) if rule.nil?
    end
    return found
  end
  
  # This method returns +true+ if all of given CIDR
  # objects are not blacklisted or are whitelisted.
  # Otherwise it returns +false+.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  # 
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
  
  def granted?(*args)
    denied(args, true).empty?
  end
  
  alias_method :granted_one?,     :granted?
  alias_method :granted_one_of?,  :granted?
  
  # Returns new instance containing elements from this object
  # and objects passed as an argument. If objects contain IP
  # information but it's impossible to obtain whether they
  # relate to black or white list, then blacklisting is assumed.
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def +(*args)
    obj = self.class.new(self)
    obj.add!(obj_to_cidr(args))
    return obj
  end
  
  # Returns new list with removed CIDR objects which are exactly the same as objects passed as an argument.
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def -(*args)
    self_copy = self.class.new(self)
    self_copy.delete(args)
    return self_copy
  end
  
  # Returns list of addresses and masks as a string with elements joined using space or given string.
  
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
    add!(args)
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
    printed = "IPv4 Tree\n---------\n"
    list4 = dump_children(@v4_root)
    list6 = dump_children(@v6_root)

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
  
end # class IPAccessList


