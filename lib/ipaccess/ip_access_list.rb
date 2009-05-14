# encoding: utf-8
#
# Easy to manage and fast IP access lists.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   LGPL
# 
# Classes contained in this library allow you to create
# and manage IP access lists in an easy way. You may use
# IPAccess class to maintain black list and white list
# and validate connections against it. You also may use
# IPAccessList class directly to build your own lists.
#
# The classes use NetAddr::CIDR objects to store IP
# addresses/masks and NetAddr::Tree to maintain
# access lists.

require 'ipaddr'
require 'resolv'
require 'netaddr'
require 'ipaccess/netaddr_patch'

# This class creates easy to manage IP access list based on IPAddrList object
# which uses binary search to speed up seeking. It stores data in IPAddr objects
# and allows to add, remove and search through them.
#

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
    args = obj_to_cidr(*args)
    super
    args.each { |addr| add!(addr) }
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
    if obj.size == 1 && obj.first.is_a?(NetAddr::CIDR)
      return obj
    end
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
    return [obj] if obj.is_a?(NetAddr::CIDR)
    
    # number - immediate generation
    return [self.class.create(obj)] if obj.is_a?(Numeric)
    
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
      when :all, :any, :anyone, :world, :internet, :net, :everything, :everyone, :everybody, :anybody
        obj = [ "0.0.0.0/0",
                "::/0" ]
      when :broadcast, :brd
        obj = [ "255.255.255.255/32",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128" ]
      when :local, :localhost, :localdomain, :loopback, :lo
        obj = [ "127.0.0.1/8",
                "::1/128" ]
      when :auto, :automatic, :linklocal
        obj = [ "169.254.0.0/16",
                "fe80::/10" ]
      when :private, :intra, :intranet, :hidden, :internal, :secret, :ula, :unique
        obj = [ "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "2001:10::/28",
                "2001:db8::/32",
                "fc00::/7",
                "fdde:9e1a:dc85:7374::/64" ]
      when :multicast, :multi, :multiemission
        obj = [ "224.0.0.0/4",
                "ff00::/8",
                "ff02::1:ff00:0/104" ]
      when :example, :reserved
        obj = [ "192.0.2.0/24",
                "128.0.0.0/16",
                "191.255.0.0/16",
                "192.0.0.0/24",
                "198.18.0.0/15",
                "223.255.255.0/24",
                "240.0.0.0/4" ]
      when :strange, :unusual, :nonpublic, :unpublic
        return obj_to_cidr(:local, :auto, :private, :reserved, :multicast)
      else
        obj = obj.to_s
      end
      return obj.map { |addr| self.class.create(addr) } if obj.is_a?(Array)
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
        obj = self.class.create(obj)
      rescue NetAddr::ValidationError
        addresses = Resolv::getaddresses(obj)
        addresses.map! do |addr|
          begin
            self.class.create(addr)
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
    return obj.is_a?(self.class) ? [obj] : [self.class.create(obj.to_s)]
  end
  

  def seek(addr)
    m = longest_match(addr)
    return false if m.to_i.zero?
    m.matches?(addr)
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
    return [] if @ip_list.empty?
    out_ary = []
    addrs = obj_to_cidr(*args)
    addrs.each do |addr|
      m = longest_match(addr)
      if (m.to_i.nonzero? && m.matches(addr))
        out_ary.push( block_given? ? yield(m) : m) 
      end
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

  def grep_strict(*args)
    return [] if @ip_list.empty?
    out_ary = []
    addrs = obj_to_cidr(*args)
    addrs.each do |addr|
      m = longest_match(addr)
      if (m == addr)
        out_ary.push( block_given? ? yield(m) : m) 
      end
    end
    return out_ary
  end
  
  alias_method :search_strict, :grep_strict

  # This method check if this list contains exact IP
  # address/mask combination(s).
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.

  def have_exact_addr?(*addr)
    grep_strict(*addr) { |m| return true }
    return false
  end

  # This method returns matching CIDR if at least one
  # of the given objects containing IP information is on the list.
  # Otherwise it returns +false+.
  # 
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.

  def include?(*args)
    addrs = obj_to_cidr(*args)
    addrs.each do |addr|
      rule = include_cidr(addr)
      return rule if rule
    end
    return false
  end
  
  alias_method :include_one?,     :include?
  alias_method :include_one_of?,  :include?
  
  # This method returns array of matching IPAddr rules
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
  
  # This method returns matching IPAddr rule if the given IP address
  # (expressed as string or IPAddr object) is on the list.
  # Otherwise it returns +false+.

  def include_simple?(addr)
    return false if empty?
    addr = IPAddr.new(addr) unless addr.is_a?(IPAddr)
    return include_cidr?(addr.ipv6? ? addr : addr.ipv4_compat)
  end
  
  # This method returns matching IPAddr rule if the given IPv6 address
  # (expressed as IPAddr object) is on the list. Otherwise it returns +false+.
  #
  # Note that IPv4 addresses should be passed here as IPv4-compatible IPv6
  # addresses.
  
  def include_cidr?(addr)
    m = longest_match(addr)
    return (m.to_i.nonzero? && m.matches(addr))
  end
  
  def select;   self.class.new(super)   end
  def map;      self.class.new(super)   end
  
  # Returns new list containing elements from this object and objects passed as an argument.
  #
  # See obj_to_cidr description for more info about arguments
  # you may pass to it.
  
  def +(*args)
    self.dup << args
  end
  
  # Returns new list with removed IPAddr objects which are exactly the same as objects passed as an argument.
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
    @ip_list.map do |addr|
      addr.native.inspect.split[1].chomp('>')[5..-1]
    end.join(sep)
  end
  
  # This method erases all elements in list.
  
  def clear
    @ip_list.clear
    return self
  end
  
  alias_method :erase, :clear
    
  def empty?
    @ip_list.empty?
  end
  
  # This operator calls add method.

  def <<(*args); self.add(*args) end
        
end
