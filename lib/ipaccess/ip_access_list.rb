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

# This class creates easy to manage IP access list based on IPAddrList object
# which uses binary search to speed up seeking. It stores data in CIDR objects
# and allows to add, remove and search through them.

class IPAccessList < NetAddr::Tree

  # Creates new IPAccessList object. It uses obj_to_cidr method for fetching
  # initial elements. See obj_to_cidr description for more info on how to pass
  # arguments.
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
  
  # This method converts names to NetAddr::CIDR objects. It returns array of CIDR objects.
  # 
  # Allowed input: string(s) (DNS names or IP addresses optionally with masks), number(s) (IP address representation),
  # IPSocket object(s), URI object(s), IPAddr object(s), Net::HTTP object(s), IPAddrList object(s), IPAccessList object(s),
  # symbol(s), object(s) that contain file descriptors bound to socket(s), and arrays of these.
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
  # That allows you to create access rules in an easy way. Known symbols are:
  #
  # ===== +:all+
  # Aliases: +:any+, +:anyone+, +:world+, +:internet+, +:net+, +:everything+, +:everyone+, +:everybody+, +:anybody+
  #
  # Creates masked IP address that matches all networks:
  #     – 0.0.0.0/0
  #     – ::/0
  # 
  # ===== +:broadcast+
  # Aliases: +:brd+
  #
  # Creates masked IP address that matches generic broadcast address:
  #     – 255.255.255.255/32
  #     – ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128
  #
  # ===== +:local+
  # Aliases: +:localhost+, +:localdomain+, +:loopback+, +:lo+
  # 
  # Creates masked IP addresses that match localhost:
  #     – 127.0.0.1/8
  #     – ::1/128
  #
  # ===== +:auto+
  # Aliases: +:automatic+, +:linklocal+
  #  
  # Creates masked IP addresses that match automatically assigned address ranges:
  #     – 169.254.0.0/16
  #     – fe80::/10
  # 
  # ===== +:private+
  # Aliases: +:intra+, +:intranet+, +:hidden+, +:internal+, +:secret+, +:ula+, +:unique+
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
  # Creates masked IP addresses that match multicast addresses ranges:
  #     – 224.0.0.0/4
  #     – ff00::/8
  #     – ff02::1:ff00:0/104
  # 
  # ===== +:reserved+
  # Aliases: +:example+
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
  # Creates masked IP addressess that match the following sets:
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
    found = find_parent(cidr) unless found
    return found
  end
  private :pathfinder
  
  # This method finds the longest matching path
  # and returns original CIDR object found there
  # if the given CIDR matches it.
  
  def matchfinder(cidr)
    found = nil
    found = find_me(cidr)
    found = find_parent(cidr) unless found
    if found.matches?(cidr)
      return found
    else
      return nil
    end
  end
  private :matchfinder
  
  # Finds the NetStruct to which given CIDR belongs.
  
  def find_me(cidr)
    me = nil
    root = nil
    if (cidr.version == 4)
      root = @v4_root
    else
      root = @v6_root
    end

    # find matching
    parent = find_parent(cidr,root)
    index = NetAddr.cidr_find_in_list(cidr,parent.tag[:Subnets])
    me = parent.tag[:Subnets][index] if (index.kind_of?(Integer))

    return(me)
  end


  # Finds the parent NetStruct to which a child NetStruct belongs.
  #
  def find_parent(cidr,parent=nil)
    if (!parent)
      if (cidr.version == 4)
        parent = @v4_root
      else
        parent = @v6_root
      end
    end
    bit_diff = cidr.bits - parent.bits

    # if bit_diff greater than 1 bit then check if one of the children is the actual parent.
    if (bit_diff > 1 && parent.tag[:Subnets].length != 0)
      list = parent.tag[:Subnets]
      found = NetAddr.cidr_find_in_list(cidr,list)
      if (found.kind_of?(NetAddr::CIDR))
        parent = find_parent(cidr,found)
      end
    end

    return(parent)
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
    addrs = obj_to_cidr(*args)
    addrs.each do |addr|
      m = matchfinder(addr)
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
      m = matchfinder(addr)
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
  
  # This method adds new element to access list. If last argument
  # is given and it is +:white+ or +:black+ then element is added
  # to white or black list. By default elements are added to black
  # list.
  
  def add!(*args)
    case args.last
      when :white, :black
        acl_list = args.pop
      else
        acl_list = :black
    end
    addrs = obj_to_cidr(*args)
    addrs.each do |addr|
      addr = addr.ipv4 if addr.ipv4_compliant?
      addr.tag[:Subnets] = []
      addr.tag[:ACL] = acl_list
      add_to_tree(addr)
    end
    return nil
  end
  
  alias_method :add, :add!
  alias_method :blacklist, :add!
  
  # Adds IP addresses in given object(s) to white list.
  
  def whitelist(*args)
    add!(*args, :white)
  end
  
  # This method returns matching CIDR if at least one
  # of the given objects containing IP information is on the list.
  # Otherwise it returns +false+.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def include?(*args)
    return false if empty?
    addrs = obj_to_cidr(*args)
    addrs.each do |addr|
      rule = include_cidr?(addr)
      return rule if rule
    end
    return false
  end
  
  alias_method :include_one?,     :include?
  alias_method :include_one_of?,  :include?
  
  # This method returns array of matching CIDR rules
  # if all of the given objects containing IP information
  # are on the list. Otherwise it returns +false+.
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def include_all?(*args)
    return false if empty?
    addrs = obj_to_cidr(*args)
    found = []
    addrs.each do |addr|
      rule = include_cidr?(addr)
      found.push rule if rule
    end
    return found.size == addrs.size ? found : false
  end
  
  # This method returns matching CIDR rule if the given IP address
  # (expressed as IP string or CIDR object) is on the list.
  # Otherwise it returns +false+.
  
  def include_simple?(addr)
    return false if empty?
    addr = NetAddr::CIDR.create(addr) unless addr.is_a?(NetAddr::CIDR)
    return include_cidr?(addr)
  end
  
  # This method returns matching CIDR rule if the given IP address
  # (expressed as CIDR object) is on the list. Otherwise it returns +false+.
  
  def include_cidr?(addr)
    addr = addr.ipv4 if addr.ipv4_compliant?
    m = matchfinder(addr)
    return m.nil? ? false : m
  end
  
  # This method returns CIDR object of the rule if the given CIDR
  # contains blacklisted and not whitelisted address. Otherwise
  # it returns +false+.
  
  def denied_cidr?(addr)
    addr = addr.ipv4 if addr.ipv4_compliant?
    
  end
  
  #def select;   self.class.new(super)   end
  #def map;      self.class.new(super)   end
  
  # Returns new list containing elements from this object and objects passed as an argument.
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def +(*args)
    self.dup.add! args
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
  
  # This method prunes all elements in list.
  
  def clear
    prune!
  end
  
  alias_method :erase, :clear
  
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
        
end

a = IPAccessList.new

cc = NetAddr::CIDR.create('12.34.0.0/8', :Tag => {'interface' => 'eth0'})

a  << cc #'0.0.0.0/0'
#a.add('127.0.0.1/8', :white)

p a.include?('12.34.5.6')

#puts a.show

