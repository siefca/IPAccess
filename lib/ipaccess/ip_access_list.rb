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
# The classes use IPAddr objects to store data and IPAddrList
# to create lists with binary search capabilities.

require 'ipaddr_list'

class IPAddrList

  module Algorithm
    
    # This module contains operations for management of IPv6
    # address list. It allows you to navigate through a list and
    # ensures that any element is converted to IPv6-compatible
    # address contained in IPAddr object.
    #
    # Almost all methods that require input will allow you to
    # pass various objects representing addresses, e.g. sockets,
    # DNS names, symbols, etc. See obj_to_ip for more info.
    
    module IPv6BinarySearch
    
      include Lint
      include BinarySearch
      
      # :stopdoc:
      
      def after_init(*args)
        @ip_list = obj_to_ip6(*args)
      end
      
      # :startdoc:
      
      # This method converts names to IPAddr objects. It returns array of IPAddr objects.
      # 
      # Allowed input: string(s) (DNS names or IP addresses optionally with masks), number(s) (IP address representation),
      # IPSocket object(s), URI object(s), IPAddr object(s), Net::HTTP object(s), IPAddrList object(s), IPAccessList object(s),
      # symbol(s), object(s) that contain file descriptors bound to socket(s) and arrays of those.
      #
      # ==== Examples
      # 
      #     obj_to_ip("127.0.0.1")                # uses IP address
      #     obj_to_ip(2130706433)                 # uses numeric representation of 127.0.0.1
      #     obj_to_ip(:private, "localhost")      # uses special symbol and DNS hostname
      #     obj_to_ip(:private, :localhost)       # uses special symbols
      #     obj_to_ip [:private, :auto]           # other way to write the above
      #     obj_to_ip "10.0.0.0/8"                # uses masked IP address
      #     obj_to_ip "10.0.0.0/255.0.0.0"        # uses masked IP address
      #     obj_to_ip IPSocket.new("www.pl", 80)  # uses socket
      #     obj_to_ip IPAddr("10.0.0.1")          # uses IPAddr object
      #     obj_to_ip :"randomseed.pl"            # uses symbol that hasn't special meaning
      #     obj_to_ip URI('http://www.pl/')       # uses URI
      #     obj_to_ip 'http://www.pl/'            # uses extracted host string
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
      
      def obj_to_ip(*obj)
        obj = obj.flatten
        if obj.kind_of?(Array)
          if obj.size == 1
            obj = obj.first
          else
            ary = []
            obj.each { |o| ary += obj_to_ip(o) }
            ary.flatten!
            return ary
          end
        end
        # IPAddr
        return [obj] if obj.is_a?(IPAddr)
        # IPAddrList
        return obj.to_a if obj.is_a?(IPAddrList)
        # object containing socket (e.g. Net::HTTP)
        obj = obj.instance_variable_get(:@socket) if obj.instance_variable_defined?(:@socket)
        obj = obj.io if (obj.respond_to?(:io) && obj.io.respond_to?(:peeraddr))
        # some file descriptor but not socket
        obj = IPSocket.for_fd(obj.fileno) if (!obj.respond_to?(:peeraddr) && obj.respond_to?(:fileno))
        # socket
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
        # symbol
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
            return obj_to_ip(:local, :auto, :private, :reserved, :multicast)
          else
            obj = obj.to_s
          end
          return obj.map { |addr| IPAddr.new(addr) } if obj.is_a?(Array)
        end
        # URI or something that responds to host method
        obj = obj.host if obj.respond_to?(:host)
        # number
        if obj.is_a?(Numeric)
          obj = IPAddr.new(obj, obj <= 4294967295 ? Socket::AF_INET : Socket::AF_INET6)
        end
        # string or similar
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
            obj = IPAddr.new(obj)
          rescue ArgumentError
            addresses = Resolv::getaddresses(obj)
            addresses.map! do |addr|
              begin
                IPAddr.new(addr)
              rescue ArgumentError
                nil
              end
            end
            addresses.flatten!
            addresses.compact!
            return addresses
          end
        end
        return obj.is_a?(IPAddr) ? [obj] : [IPAddr.new(obj)]
      end

      # This method works the same way as obj_to_ip but
      # ensures that all objects in resulting array are
      # holding IPv6 information. All IPAddr objects
      # containing IPv4 addresses are replaced by newly
      # created IPAddr IPv6 objects that are IPv4-compatible.
      # 
      # It is usefull when you want to keep all data in
      # the same format and be able to compare addresses
      # without creating family-based lists or monkey-patching
      # IPAddr. Most of IPAccessList's methods use it to
      # obtain information about IP addresses.

      def obj_to_ip6(*args)
        addrs = obj_to_ip(*args)
        addrs.each_with_index do |addr,i|
          addrs[i] = addr.ipv4_compat if addr.ipv4?
        end
        return addrs
      end

        # This method adds new element(s) to list. If address/mask
        # is already present it won't be added to list. This method
        # returns reference to IPAccessList object.
        #
        # See obj_to_ip description for more info about arguments
        # you may pass to it.

        def add(*args)
          args = obj_to_ip6(*args)
          args.each do |addr|
            unless have_exact_addr?(addr)
              @ip_list.push(addr)
              @ip_list = @ip_list.sort
            end
          end
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
        # See obj_to_ip description for more info about arguments
        # you may pass to it.

        def grep(*args)
          return [] if @ip_list.empty?
          out_ary = []
          addrs = obj_to_ip6(*args)
          addrs.each do |addr|
            binary_search(addr) do |ipaddr, range|
              range.any? do |idx|
                if @ip_list[idx].include?(ipaddr)
                  out_ary.push( block_given? ? yield(@ip_list[idx]) : @ip_list[idx]) 
                end
              end
            end
          end
          return out_ary
        end

        alias_method :search, :grep

        # This method finds all addresses in the list that are
        # equal to given addresses/netmasks and returns an array containing
        # these addresses. If the optional block is supplied,
        # each matching element is passed to it, and the block‘s
        # result is stored in the output array.
        # 
        # See obj_to_ip description for more info about arguments
        # you may pass to it.

        def grep_strict(*args)
          return [] if @ip_list.empty?
          out_ary = []
          addrs = obj_to_ip6(*args)
          addrs.each do |addr|
            binary_search(addr) do |ipaddr, range|
              range.any? do |idx|
                if @ip_list[idx] == ipaddr
                  out_ary.push( block_given? ? yield(@ip_list[idx]) : @ip_list[idx]) 
                end
              end
            end
          end
          return out_ary
        end
        
        alias_method :search_strict, :grep_strict

        # This method check if this list contains exact IP
        # address/mask combination(s).
        #
        # See obj_to_ip description for more info about arguments
        # you may pass to it.

        def have_exact_addr?(*addr)
          grep_strict(*addr) { |m| return true }
          return false
        end

        # This method returns unique hash of given IPAddr object.

        def ip_unique_hash(obj)
          obj.inspect.split[1].chomp('>')[5..-1].hash
        end
        protected :ip_unique_hash

        # This methid returns +true+ if at least one of the given
        # objects containing IP information are on the list. Otherwise
        # it returns +false+.
        # 
        # See obj_to_ip description for more info about arguments
        # you may pass to it.

        def include?(*args)
          return false if @ip_list.empty?
          addrs = obj_to_ip6(*args)
          addrs.each do |addr|
            return true if include_ipaddr6(addr)
          end
          return false
        end
        
        alias_method :include_one?,     :include?
        alias_method :include_one_of?,  :include?
        
        # This methid returns +true+ if all of the given
        # objects containing IP information are on the list.
        # Otherwise it returns +false+.
        #
        # See obj_to_ip description for more info about arguments
        # you may pass to it.
        
        def include_all?(*args)
          return false if @ip_list.empty?
          addrs = obj_to_ip6(*args)
          to_find = addrs.size
          addrs.each do |addr|
            to_find -= 1 if include_ipaddr6?(addr)
          end
          return to_find.zero?
        end

        # This methid returns +true+ if the given IP address
        # (expressed as string or IPAddr object) is on the list.
        # Otherwise it returns +false+.

        def include_simple?(addr)
          return false if @ip_list.empty?
          addr = IPAddr.new(addr) unless addr.is_a?(IPAddr)
          return include_ipaddr6?(addr.ipv6? ? addr : addr.ipv4_compat)
        end

        # This methid returns +true+ if the given IPv6 address
        # (expressed as IPAddr object) is on the list.
        # Otherwise it returns +false+.
        #
        # Note that IPv4 addresses should be passed here as IPv4-compatible.

        def include_ipaddr6?(addr)
          return false if @ip_list.empty?
          binary_search addr do |ipaddr, range|
            range.any? {|idx| @ip_list[idx].include? ipaddr }
          end
        end

        def select;   self.class.new(super)   end
        def map;      self.class.new(super)   end

        # Returns new list containing elements from this object and objects passed as an argument.
        #
        # See obj_to_ip description for more info about arguments
        # you may pass to it.

        def +(*args)
          self.dup << args
        end

        # Returns new list with removed IPAddr objects which are exactly the same as objects passed as an argument.
        #
        # See obj_to_ip description for more info about arguments
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

        # This method returns string containing elements of the list separated by commas.

        def to_s
          join(', ')
        end

        # Deletes specified addresses from the list. Returns an array of deleted elements.
        #
        # See obj_to_ip description for more info about arguments
        # you may pass to it.

        def del(*args)
          return [] if @ip_list.empty?
          to_delete = []
          binary_search(addr) do |ipaddr, range|
            range.any? do |idx|
              to_delete << idx if @ip_list[idx] == ipaddr
            end
          end
          return [] if to_delete.empty?
          deleted = []
          to_delete.each { |idx| deleted.push delete_at(idx) }
          @ip_list = @ip_list.sort
          return deleted
        end
        
        alias_method :delete, :del
        alias_method :remove, :del
        
        # This method creates new IPAddrList object with same contents as object
        # for which it is called.

        def dup
          self.class.new(self)
        end
        
        def empty?
          @ip_list.empty?
        end
        
        # This operator calls add method.

        def <<(*args); self.add(*args) end
    
    end # module IPv6BinarySearch
    
  end # module Algorithm

end

# This class creates easy to manage IP access list based on IPAddrList object
# which uses binary search to speed up seeking. It stores data in IPAddr objects
# and allows to add, remove and search through them.
#
# See IPAddrList::Algorithm::IPv6BinarySearch for methods provided by this class.

class IPAccessList < IPAddrList

  # Creates new IPAccessList object. It uses obj_to_ip6 method for fetching
  # initial elements. See obj_to_ip description for more info on how to pass
  # arguments.
  # 
  # Examples:
  #     
  #     IPAccessList.new '192.168.0.0/16', '127.0.0.1/255.0.0.0'
  #     IPAccessList.new :private, :local
  #     IPAccessList.new "randomseed.pl", :nonpublic
  
  def initialize(*args)
    super(*args, :IPv6BinarySearch)
    return self
  end
  
end

