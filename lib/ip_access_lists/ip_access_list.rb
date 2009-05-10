
class IPAccessList < IPAddrList

  def initialize(*args)
    super(obj_to_ip6(*args))
    self.extend(Addon)
    self
  end

  def <<(*args); self.add(*args) end

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
        obj = ["127.0.0.1/8",
               "::1/128" ]
      when :auto, :automatic, :linklocal
        obj = ["169.254.0.0/16",
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
  # created IPAddr IPv6 objects that are IPv4-mapped.
  # 
  # It is usefull when you want to keep all data in
  # the same format and be able to compare addresses
  # without creating family-based lists or monkey-patching
  # IPAddr.
  
  def obj_to_ip6(*args)
    args = obj_to_ip(*args)
    args.map! do |ipaddr|
      ipaddr.ipv6? ? ipaddr : ipaddr.ipv4_mapped
    end
    return args
  end
  
  module Addon
    
    # This method adds new element(s) to list. You can pass any
    # object that obj_to_ip6 method can understand. If address/mask
    # is already present it won't be added to list. This method
    # returns reference to IPAccessList object.
    
    def add(*args)
      args = obj_to_ip6(*args)
      args.each do |addr|
        super(addr) unless have_exact_addr?(addr)
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
    
    def grep(*args)
      out_ary = []
      addrs = obj_to_ip6(*args)
      addrs.each do |addr|
        binary_search addr do |ipaddr, range|
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
    # equal to given addresses and returns an array containing
    # these addresses. If the optional block is supplied,
    # each matching element is passed to it, and the block‘s
    # result is stored in the output array.
    #
    # Ba aware that it may call the block for same object twice
    # if you'll pass two matching addresses.
    
    def grep_strict(*args)
      out_ary = []
      addrs = obj_to_ip6(*args)
      addrs.each do |addr|
        binary_search addr do |ipaddr, range|
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
    # address and mask combination.
    
    def have_exact_addr?(addr)
      return false
      grep_strict(addr) { |matching| return true }
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
    
    def include?(*args)
      addrs = obj_to_ip6(*args)
      addrs.each do |addr|
        return true if super(addr)
      end
      return false
    end
    
    alias_method :include_one?,     :include?
    alias_method :include_one_of?,  :include?
    
    # This methid returns +true+ if all of the given
    # objects containing IP information are on the list.
    # Otherwise it returns +false+.
    
    def include_all?(*args)
      addrs = obj_to_ip6(*args)
      to_find = addrs.size
      addrs.each do |addr|
        to_find -= 1 if include?(addr)
      end
      return to_find.zero?
    end
    
    def select;   self.class.new(super)   end
    def map;      self.class.new(super)   end
    
    # Returns new list containing elements from this object and objects passed as an argument.
    
    def +(*args)
      obj = self.dup
      obj.add(args)
      return obj
    end
    
    # Returns new list with removed IPAddr objects which are exactly the same as objects passed as an argument.
    
    def -(*args)
      other = self.class.new(*args) unless (args.size == 1 && args.first.is_a?(self.class))
      newobj = select { |addr| other.have_exact_addr?(our_ipaddr) }
      return newobj
    end
    
    # Returns list of addresses and masks as a string with elements joined using space or given string.
    
    def join(sep=' ')
      @ip_list.map do |addr|
        addr.native.inspect.split[1].chomp('>')[5..-1]
      end.join(sep)
    end
    
    # Deletes specified addresses from the list. Returns an array of deleted elements.
    
    def del(*args)
      addrs = obj_to_ip6(*args)
      to_del = []
      addrs.each do |addr|
        grep(addr) do |match|
          to_del += @ip_list.delete(match) if match == addr
        end
      end
      return to_del.flatten
    end
    
  end

end

