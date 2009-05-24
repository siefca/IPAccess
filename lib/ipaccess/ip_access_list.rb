# encoding: utf-8
# 
# === ip_access_list
# 
# This file contains IPAccessList class, which uses
# NetAddr::Tree to implement IP access list.
#
# Easy to manage and fast IP access lists.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   LGPL

$LOAD_PATH.unshift '..'

require 'ipaddr'
require 'resolv'
require 'netaddr'
require 'ipaccess/netaddr_patch'

# This class implements easy to manage IP access list based on NetAddr::Tree
# which uses binary search to speed up matching process. It stores data in a tree
# of NetAddr::CIDR objects and allows to add, remove and search them.
#  
# To control access IPAccessList maintaines two abstract lists: white list and black
# list. Each list contains rules (CIDR objects with information about
# IP address and network mask). Access is evaluated as blocked when tested
# IP address matches rule from black list and not matches any rule from white
# list. Basically, white list rules override black list rules.
# 
# To be precise: internally there are no real lists but one tree containing marked
# objects in order to increase lookups performance.
# 
# There are 2 major types of operations you can perform: rules management and
# access checks. Rules management methods allows you to add, remove and find IP access
# rules. Access checks let you test if given address or addresses are allowed
# or denied to perform network operations according to rules.
#
# IPv6 addresses that are IPv4 compatible or IPv4 masked are automatically
# translated into IPv4 addresses while adding or searching.
# 
# Example of usage:
#
#     access = IPAccessList.new       # creates new access list
#     access.blacklist :ipv4_private  # blacklists private IPv4 addresses
#     access.whitelist 172.16.0.7     # whitelists 172.16.0.7
#
# Example of deny-all & allow-selected strategy:
# 
#     access = IPAccessList.new       # creates new access list
#     access.blacklist :all           # blacklist all

class IPAccessList < NetAddr::Tree

  # Creates new IPAccessList object. You may pass objects
  # containing IP information to it. See obj_to_cidr description
  # for more info on how to pass arguments.
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
    add!(*args) unless args.empty?
    return self
  end
  
  # This method converts names to NetAddr::CIDR objects. It returns an array of CIDR objects.
  # 
  # Allowed input: string(s) (DNS names or IP addresses optionally with masks), number(s) (IP address representation),
  # IPSocket object(s), URI object(s), IPAddr object(s), Net::HTTP object(s), IPAddrList object(s), NetAddr::CIDR object(s)m
  # NetAddr::Tree object(s), IPAccessList object(s), symbol(s), object(s) that contain file descriptors bound to socket(s),
  # and arrays of these.
  #
  # ==== Examples
  # 
  #     obj_to_cidr("127.0.0.1")                # uses IP address
  #     obj_to_cidr(2130706433)                 # uses numeric representation of 127.0.0.1
  #     obj_to_cidr(:private, "localhost")      # uses special symbol and DNS hostname
  #     obj_to_cidr(:private, :localhost)       # uses special symbols
  #     obj_to_cidr [:private, :auto]           # other way to write the above
  #     obj_to_cidr "10.0.0.0/8"                # uses masked IP address
  #     obj_to_cidr "10.0.0.0/255.0.0.0"        # uses masked IP address
  #     obj_to_cidr IPSocket.new("www.pl", 80)  # uses socket
  #     obj_to_cidr IPAddr("10.0.0.1")          # uses IPAddr object
  #     obj_to_cidr :"randomseed.pl"            # uses symbol that hasn't special meaning
  #     obj_to_cidr URI('http://www.pl/')       # uses URI
  #     obj_to_cidr 'http://www.pl/'            # uses extracted host string
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
  # Subvariants: +:ipv4_+ and +:ipv6_:+
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
  # Subvariants: +:ipv4_+ and +:ipv6_:+
  # 
  # Creates masked IP addresses that match localhost:
  #     – 127.0.0.1/8
  #     – ::1/128
  #
  # ===== +:auto+
  # Aliases: +:automatic+, +:linklocal+
  # Subvariants: +:ipv4_+ and +:ipv6_:+
  #  
  # Creates masked IP addresses that match automatically assigned address ranges:
  #     – 169.254.0.0/16
  #     – fe80::/10
  # 
  # ===== +:private+
  # Aliases: +:intra+, +:intranet+, +:internal+
  # Subvariants: +:ipv4_+ and +:ipv6_:+
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
  # Subvariants: +:ipv4_+ and +:ipv6_:+
  #
  # Creates masked IP addresses that match multicast addresses ranges:
  #     – 224.0.0.0/4
  #     – ff00::/8
  #     – ff02::1:ff00:0/104
  # 
  # ===== +:reserved+
  # Aliases: +:example+
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
  
  def obj_to_cidr(*obj)
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

    # IPAddr - fetch IP string
    obj = obj.native.inspect.split[1].chomp('>')[5..-1] if obj.is_a?(IPAddr)

    # object containing socket (e.g. Net::HTTP) - fetch socket
    obj = obj.instance_variable_get(:@socket) if obj.instance_variable_defined?(:@socket)
    obj = obj.io if (obj.respond_to?(:io) && obj.io.respond_to?(:peeraddr))

    # some file descriptor but not socket - fetch socket
    obj = IPSocket.for_fd(obj.fileno) if (!obj.respond_to?(:peeraddr) && obj.respond_to?(:fileno))

    # socket - fetch IP string
    if obj.respond_to?(:peeraddr)
      prev = nil
      if obj.respond_to?(:do_not_reverse_lookup)
        prev = obj.do_not_reverse_lookup
        obj.do_not_reverse_lookup = true
      end
      peeraddr = obj.peeraddr[3]
      obj.do_not_reverse_lookup = prev unless prev.nil?
      obj = peeraddr
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
        obj = obj.to_s
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
  
  # This method finds the longest matching path
  # and returns original CIDR object found there.
  
  def pathfinder(cidr)
    found = nil
    found = find_me(cidr)
    found = find_parent(cidr) if found.nil?
    return found
  end
  private :pathfinder
    
  # Finds the NetStruct to which given CIDR belongs and is not
  # whitelisted.
  
  def denied_find_me(cidr)
    me = nil
    root = (cidr.version == 4 ? @v4_root : @v6_root)
    parent = find_parent(cidr,root)
    return nil if parent.tag[:ACL] != :black
    index = NetAddr.cidr_find_in_list(cidr, parent.tag[:Subnets])
    me = parent.tag[:Subnets][index] if (index.kind_of?(Integer))
    return nil if (me.nil? || me.tag[:ACL] != :black)
    return me
  end
  private :denied_find_me

  # Finds the parent NetStruct to which a child NetStruct belongs
  # and is not whitelisted.

  def denied_find_parent(cidr, parent=nil)
    parent = (cidr.version == 4 ? @v4_root : @v6_root) if parent.nil?
    bit_diff = cidr.bits - parent.bits

    if (bit_diff > 1 && parent.tag[:Subnets].length.nonzero?)
      list = parent.tag[:Subnets]
      found = NetAddr.cidr_find_in_list(cidr,list)
      if (found.kind_of?(NetAddr::CIDR))
        return nil if found.tag[:ACL] != :black
        parent = denied_find_parent(cidr,found)
      end
    end

    return parent
  end
  private :denied_find_parent
  
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
    addrs = obj_to_cidr(*args)
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
  
  # If the optional block is supplied,
  # each matching element is passed to it, and the block‘s
  # result is stored in the output array.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.

  def grep_exact(*args)
    return [] if empty?
    out_ary = []
    addrs = obj_to_cidr(*args)
    addrs.each do |addr|
      m = included_cidr(addr)
      if (m == addr)
        out_ary.push( block_given? ? yield(m) : m)
      end
    end
    return out_ary
  end
  
  # This method check if this list contains exact IP
  # address/mask combination(s). It returns +true+ if
  # it is so.
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.

  def have_exact_addr?(*addr)
    return false if empty?
    grep_exact(*addr) { |m| return true }
    return false
  end
  
  # This method adds new rule(s) to access list. By default
  # elements are added to black list. If last argument
  # given argument is +:white+ or +:black+ then element is added
  # to the specified list.
  
  # Special case: CIDR objects may carry information about
  # access list they should belong to. If the last argument
  # is not describing access list and added rule is this
  # special CIDR containing information about assignment
  # to some list then this extra sugar will be used instead
  # of default +:black+.
  # 
  # If the given rule is exact (IP and mask) as pre-existent
  # rule in the same list then it is not added.
  # 
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def add!(*args)
    case args.last
      when :white, :black
        acl_list = args.pop
      else
        acl_list = nil
    end
    addrs = obj_to_cidr(*args)
    addrs.each do |addr|
      add_list = acl_list
      addr = addr.ipv4 if addr.ipv4_compliant?
      add_list = addr.tag[:ACL] if (add_list.nil? &&
                                    (addr.tag[:ACL] == :white ||
                                     addr.tag[:ACL] == :ashen)) # object with extra sugar
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
  
  # Adds IP addresses in given object(s) to white list if called
  # with at least one argument. Returns white list if called
  # without arguments (array of CIDR objects).
  #
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
  
  def whitelist(*args)
    args.empty? ? to_a(:white) : add!(*args, :white)
  end
  
  alias_method :allow, :whitelist
  alias_method :permit, :whitelist
  
  # Adds IP addresses in given object(s) to black list if called
  # with at least one argument. Returns black list if called
  # without arguments (array of CIDR objects).
  #
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
    
  def blacklist(*args)
    args.empty? ? to_a(:black) : add!(*args, :black)
  end
  
  alias_method :deny, :blacklist
  
  # This method returns an array of matching CIDR objects
  # for the given objects containing IP information
  # that are on the list.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def included(*args)
    found = []
    return found if empty?
    addrs = obj_to_cidr(*args)
    return found if addrs.empty?
    addrs.each do |addr|
      rule = included_cidr(addr)
      found.push(rule) unless rule.nil?
    end
    
    return found
  end
  
  # This method returns +true+ if all
  # of the given objects containing IP information
  # are on the list. Otherwise it returns +false+.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.

  def include?(*args)
    return false if empty?
    addrs = obj_to_cidr(*args)
    return false if addrs.empty?
    addrs.each do |addr|
      rule = included_cidr(addr)
      return false if rule.nil?
    end
    return true
  end

  alias_method :include_all?, :include?
  
  # This method returns first CIDR rule from
  # the given objects containing IP information
  # that is on the list. Otherwise it returns nil.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def included_first(*args)
    return nil if empty?
    addrs = obj_to_cidr(*args)
    return nil if addrs.empty?
    addrs.each do |addr|
      rule = included_cidr(addr)
      return rule unless rule.nil?
    end
    return nil
  end
  
  # This method returns +true+ if at least one of
  # the given objects containing IP information
  # that is on the list. Otherwise it returns +false+.
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
    return nil if (found.nil? || found.hash == root.hash)
    return (found.matches?(addr) ? found : nil)
  end
  
  # This method returns +true+ if the given IP address
  # (expressed as CIDR object) is on the list. Otherwise it returns +false+.
  #
  # It is designed to check rules, NOT access. To do access
  # check use granted_cidr and denied_cidr methods.
  
  def include_cidr?(addr)
    not included_cidr(addr).nil?
  end

  # This method returns an array containing CDIR objects that
  # are result of finding IP rules given in the array.
  # 
  # It is designed to check rules, NOT access. To do access
  # check use allowed and denied methods.
  # 
  # You should avoid passing hostnames as arguments since
  # DNS is not reliable and responses may change with time
  # which may cause security flaws.
  
  def rule_exists(list, *args)
    found = []
    return found if empty?
    addrs = obj_to_cidr(*args)
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
      return found
    end
  end
  private :rule_exists_cidr
  
  # This method returns an array containing CDIR objects that
  # are result of finding given IP rules in the black list.
  # 
  # It is designed to check rules, NOT access. To do access
  # check use granted and denied methods.
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
  # It is designed to check rules not IP access. To do access
  # check use granted_cidr and denied_cidr methods.
  
  def find_blacklist_rule_cidr(addr)
    rule_exists_cidr(:black, addr)
  end

  # This method returns +true+ if all of the given
  # IP addresses are on the IP rules black list.
  # 
  # It is designed to check rules, NOT access. To do access
  # check use allowed and denied methods.
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def blacklist_rules_exist?(*args)
    addrs = obj_to_cidr(*args)
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
  # It is designed to check rules, NOT access. To do access
  # check use allowed and denied methods.
  
  def blacklist_rule_exists_cidr?(addr)
    not rule_exists_cidr(:black, addr).nil?
  end

  # This method returns an array containing CDIR objects that
  # is result of finding given IP rules in the white list.
  # 
  # It is designed to check rules, NOT access. To do access
  # check use allowed and denied methods.
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

  # This method returns +true+ if all of the given
  # IP addresses are on the IP rules white list.
  # 
  # It is designed to check rules, NOT access. To do access
  # check use allowed and denied methods.
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def whitelist_rules_exist?(*args)
    addrs = obj_to_cidr(*args)
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
  
  # This method returns CIDR object of the matching rule
  # if the given CIDR contains blacklisted and not whitelisted
  # address. Otherwise it returns +nil+.
  #
  # It should be used to check access for one IP.
  
  def denied_cidr(addr)
    addr = addr.ipv4 if addr.ipv4_compliant?
    root = addr.version == 4 ? @v4_root : @v6_root
    return nil if root.tag[:Subnets].empty?
    found = nil
    found = denied_find_me(addr)
    found = denied_find_parent(addr) if found.nil?
    return nil if (found.nil? || found.hash == root.hash)
    return (found.matches?(addr) ? found : nil)
  end
  
  # This method returns +true+ if the given CIDR contains
  # blacklisted and not whitelisted address. Otherwise
  # it returns +false+.
  # 
  # It should be used to check access for one IP.

  def denied_cidr?(addr)
    not denied_cidr(addr).nil?
  end

  # This method returns an array of CIDR objects that match
  # black list rules and not match white list rules.
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
  
  def denied(*args)
    found = []
    return found if empty?
    args = obj_to_cidr(*args)
    args.each do |addr|
      rule = denied_cidr(addr)
      found.push(rule) unless rule.nil?
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
    not denied(args).empty?
  end
  
  alias_method :denied_one?,     :denied?
  alias_method :denied_one_of?,  :denied?
  
  # This method returns given CIDR object of the matching rule
  # if the given CIDR is not blacklisted or whitelisted.
  # Otherwise it returns +nil+.
  #
  # It should be used to check access for one IP. 
  
  def granted_cidr(addr)
    denied_cidr(addr).nil? ? addr : nil
  end
  
  # This method returns +true+ if the given CIDR is not
  # blacklisted or whitelisted. Otherwise it returns +false+.
  # 
  # It should be used to check access for one IP.
  
  def granted_cidr?(addr)
    denied_cidr(addr).nil?
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
    args = obj_to_cidr(*args)
    args.each do |addr|
      rule = denied_cidr(addr)
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
    denied(args).empty?
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
    obj.add!(obj_to_cidr(*args))
    return obj
  end
  
  # Returns new list with removed CIDR objects which are exactly the same as objects passed as an argument.
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def -(*args)
    other = self.class.new(*args)
    newobj = select { |addr| !other.have_exact_addr?(addr) }
    return newobj
  end
  
  # Returns list of addresses and masks as a string with elements joined using space or given string.
  
  def join(sep=' ')
    dump.map do |obj|
      obj[:CIDR].to_s
    end.join(sep)
  end
  
  alias_method :clear, :prune!
  alias_method :erase, :prune!

  # This method returns +true+ if the list is empty.

  def empty?
    @v4_root.tag[:Subnets].empty? &&
    @v6_root.tag[:Subnets].empty?
  end

  # This operator calls add method.

  def <<(*args)
    add!(*args)
    return self
  end

  # This method returns an array of CIDR objects belonging
  # to given access list. If no list is specified it returns
  # an array containing all lists.

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
    list.map do |entry|
      NetAddr.cidr_build(entry.version,
                        entry.to_i(:network),
                        entry.to_i(:netmask),
                        entry.tag[:ACL].nil? ? {} : {:ACL => entry.tag[:ACL]})  
    end
    return list
  end
  private :dump_flat_list
  
  # This method produces array of CIDR objects that
  # belong to an access list specified by type (:white or :black).
  # If no type is given it returns all entries.
  
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
    
    printed << "\n\nIPv6 Tree\n---------\n" if list6.length.nonzero?
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

a = IPAccessList.new

a .blacklist :ipv4_private, :all

a.add('10.11.0.0/8', :white)
a.add('127.0.0.1/8', :black)
#a.add('127.0.0.1/8', :white)
a.add('127.0.0.1/24', :black)

#a.add('1.2.3.4/16', :white)
#p a.include?('12.34.5.6')

puts a.show
puts
puts (a+[]).show

#puts a.blacklist
#puts
#puts a.whitelist
#puts a.show_b

#z = NetAddr::CIDR.create('11.11.1.1')
#z = NetAddr::CIDR.create('127.0.0.1')  
#puts a.denied?(z)


#puts a.blacklist_rule_exists?('17.16.0.0/12')


