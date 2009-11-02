# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# This file contains IPAccess::Set class, which uses
# IPAccess::List objects to implement IP input/output
# access control.
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
require 'ipaccess'
require 'ipaccess/ip_access_list'
require 'ipaccess/ip_access_errors'

module IPAccess
  
  # This class maintains an access set.
  # 
  # Objects of IPAccess::Set class, called <b>access sets</b>,
  # contain two access lists which are available
  # as accessible attributes: +input+ and +output+.
  # 
  # ==== Input and output
  # 
  # First list is for maintaining incoming IP
  # traffic and second for outgoing traffic.
  # Again, it is your free will to check IP addresses
  # against input/output rules or not.
  # 
  # ==== Rules management
  # 
  # These two lists are instances of IPAccess::List.
  # Use IPAccess::List instance methods to add or remove
  # rules from this lists referenced by +input+ and
  # +output+ attributes. Both IPv4 and IPv6 addresses
  # are supported.
  # 
  # ==== Checking access
  # 
  # To check access you may call methods that belong
  # to lists but it is recommended to use methods
  # defined by this class when operating on access sets.
  # There are two groups of such methods, one for
  # checking incoming traffic and the other one
  # for checking outgoing traffic.
  # 
  # There are also different variants of this methods
  # for different IP representations. That's because
  # speed is important here. If you have a socket object
  # you want to test then you should use method that
  # checks sockets. If your IP is in text format you
  # may want to use method that checks IP addresses
  # written as strings.
  # 
  # ==== Exceptions
  # 
  # Access checking methods throw exceptions that are
  # kind of IPAccessDenied. Each exception contain
  # IP address, rule that matched, diagnostic message
  # and an optional object that points to so
  # called originator described below.
  # 
  # ==== Accessing original object
  # 
  # You can pass an optional object to almost all
  # of the access checking methods. It usually will be
  # passed as the last argument called +orig+.
  # The originator is intended to
  # be used as a helpful reference to original object for
  # which access is checked.
  # 
  # You may want to ask why there is a need for
  # originator when some object is tested already.
  # There are some situations when you want to test
  # something that represents network object's IP
  # but it's not related to network object itself.
  # For example imagine that your program creates
  # objects for HTTP sessions. In your HTTP class
  # you may add some access checks but the tested
  # object is a socket. In that case you may want
  # to pass HTTP object to an access checking method
  # as the originator instead of socket.
  # 
  # Originator is transported within an exception so you can
  # use it in rescue section to send some data
  # or do other stuff before closing network
  # object. In case of patched network objects and
  # special variants of network classes that
  # this library also provides, you may also find
  # +:opened_on_deny+ option helpful to achieve that.
  # 
  # In case of general purpose methods like check_in and check_out
  # you cannot pass the originator because they use
  # variant list of arguments of different kinds –
  # in that case however the originators will be set
  # to original, checked objects. The only disadvantage
  # is that you cannot set the originators manually.
  # 
  # If this additional argument +orig+ is +nil+ or wasn't passed
  # to the access checking method, the method
  # will try to obtain it automagically. How?
  # It will try to fetch it from the +:Originator+ tag
  # of NetAddr::CIDR object that had been used. This tag
  # will be preset because the method will add +:inclulde_origins+
  # option while calling IPAccess.to_cidrs on a list of
  # arguments that are going to be checked. That magic
  # works also for specialized access checking methods.
  # In those cases the originator is not fetched from
  # NetAddr::CIDR object's tag but comes from a real object
  # (Socket, String, etc.) that had been passed to method
  # for testing. Ofcourse that would happend only if
  # you don't enforce some object to be treated as originator
  # by passing additional +obj+ argument to some checking method.
  #
  # Checking methods will try to fill up missing +:Originator+ tag
  # in each processed object containing IP address while figuring
  # out the original object. By object containing IP address
  # we mean NetAddr::CIDR kind of object that is used by underlying
  # routines to check access and reported during exception raising
  # as +peer_ip+ attribute. Checking methods will use private method
  # setup_originator to decide which object should be choosen
  # as the originator.
  #
  # ==== Usage examples
  # 
  #   access = IPAccess::Set.new 'myset'    # create access set
  #   access.input.block :private           # input list: block private subnets
  #   access.input.permit '192.168.1.1'     # input list: but permit 192.168.1.1 
  #   access.check_in '192.168.1.1'         # should pass
  #   access.check_in '192.168.1.2'         # should raise an exception
  # 
  # In the example above checking access is covered
  # by the check_in method. It is generic, easy to use
  # routine, but if you are fan of performance
  # you may want to use dedicated methods designed
  # to handle single IP stored in socket, file descriptor,
  # NetAddr::CIDR object, sockaddr structure or IP string.
  #
  #   require 'uri'
  #   require 'net/http'
  # 
  #   access = IPAccess::Set.new 'outgoing http'  # create access set
  #   access.output.block :all                    # output list: block all
  #                                               
  #   url = URI('http://randomseed.pl/')          # parse URL
  #   res = Net::HTTP.new(url.host, url.port)     # create HTTP resource
  #   req = Net::HTTP::Get.new(url.path)          # create HTTP request
  # 
  #   res.start do                                # start HTTP session
  #     access.check_out(res)                     # check access for socket extracted from HTTP object
  #     response = res.request(req)               # read response
  #   end
  #
  # In the example above, which is probably more real
  # than previous, we're using check_out method for testing
  # Net::HTTP response object. The method is clever enough to
  # extract IP socket from such object.
  # 
  # Although the problem still exists because
  # access for incoming connection is validated
  # after the HTTP session has already started. We cannot
  # be 100% sure whether any data has been sent or not.
  # The cause of that problem is lack of controlled
  # low-level connect operation that we can issue in
  # that particular case.
  # 
  # To fix issues like that you may want to
  # globally enable IP access control for original
  # Ruby's socket classes or use special versions
  # of them shipped with this library. To patch original
  # sockets or single objects use IPAccess.arm class method. To 
  # use extended version of network classes use
  # <tt>IPAccess::</tt> prefix.
  
  class Set
    
    # Access list for incoming IP traffic. See IPAccess::List class
    # for more information on how to manage it.
    
    attr_reader   :input
    
    alias_method  :in, :input
    alias_method  :incoming, :input
    
    # Access list for outgoing IP traffic. See IPAccess::List class
    # for more information on how to manage it.
    
    attr_reader   :output
    
    alias_method  :out, :output
    alias_method  :outgoing, :output
    
    # Descriptive name of this object. Used in error reporting.
    
    attr_accessor :name
    
    # This method creates new IPAccess::Set object. It optionally takes
    # two IPAccess::List objects (initial data for access lists)
    # and descriptive name of an access set used in error reporting.
    # If there is only one argument it's assumed that it contains
    # descriptive name of an access set.
    
    def initialize(input=nil, output=nil, name=nil) 
      @name = nil
      @name, input = input, nil if (output.nil? && name.nil?)
      @input  = IPAccess::List.new(input)
      @output = IPAccess::List.new(output)
      return self
    end
    
    # Raises default exception including important informations like
    # remote IP address, rule that IP matched to, used access set
    # and optional object passed as an argument.
    # 
    # First argument (+addr+) should be a testet IP address in CIDR object and second 
    # argument (+rule+) of the same kind should contain a matching rule.
    # Third argument should be an exception class that will be used
    # to raise an exception. The last, optional argument should be
    # an object that will be stored within the exception's object
    # as +originator+. It's recommended for it to be an object that
    # was used for communication and therefore tested.
    
    def scream!(addr, rule, use_exception=IPAccessDenied::Input, obj=nil)
      raise use_exception.new(addr, rule, self, obj)
    end
    
    # This method returns +true+ if all access lists are empty.
    # Otherwise returns +false+.
    
    def empty?
      @input.empty? && @output.empty?
    end
    
    # This method removes all rules from both input and
    # output access list.
    
    def clear!
      @input.clear!
      @output.clear!
    end
    
    # This method returns true if access set works
    # in bidirectional mode.
    
    def bidirectional?
      return (@output.object_id == @input.object_id)
    end
    
    # This method switches set to bidirectional
    # mode if the given argument is not +false+
    # and is not +nil+. When access set
    # operates in this mode there is no difference
    # between incoming and outgoing acceess list.
    # In bidirectional mode each access check
    # is performed against one list, which contains
    # both input and output rules. Still the only
    # way to add or delete rules is to straight
    # call +input+ or +output+. The difference is
    # that these lists are linked together 
    # in bidirectional mode.
    # 
    # Be aware that switching mode will alter
    # your access lists. When switching to
    # bidirectional it will combine input and
    # output rules and put it into one list.
    # When switching back from bidirectional
    # to normal mode input and output lists
    # will have the same rules inside.
    # 
    # It may be good idea to prune access lists before
    # switching mode or to switch mode before adding
    # any rules to avoid unexpected results. You may
    # of course change mode anyway if you really know
    # what you are doing.
    
    def bidirectional=(enable)
      enable = enable ? true : false
      if enable != bidirectional?
        if enable
          @input.add @output
          @output.clear!
          @output = @input
        else
          @output = IPAccess::List.new @input
        end
      end
      return nil
    end
    
    # This method helps with setting up
    # a proper originator for an object
    # that is checked against access set.
    # Originator is the original object
    # that uses a checked IP address.
    # This definition is very general and that's
    # why there is a need for a method
    # like this, that will try to set it
    # up properly.
    # The +cidr+ argument (containing the IP
    # address) should be a kind of
    # NetAddr::CIDR. It may also contain a special
    # tag inside called +:Originator+. Any
    # existing information about the originator contained
    # in this object's tag will never be overwritten.
    # However, it may not be used if second argument,
    # +orig+ is given.
    # This +orig+ argument should be an object
    # to which the IP address from +cidr+ relates to.
    # If it's not given then the value found in
    # the +cidr+'s originator tag is assigned to it.
    # The last argument, +net_obj+ is intended
    # to be "a rescue object" that will be treated
    # as originator if everything else fails. If the +orig+
    # is set to +:none+ then the original object will
    # always be returned as +nil+ without affecting
    # tag inside +cidr+.
    # 
    # === Workflow
    # 
    # For better understanding
    # how it works you may
    # look at the workflow diagram:
    # 
    # link:images/ipaccess_setup_origin.png
    #
    # To predict the logic in an easy way
    # you may also find the input/output states
    # table useful:
    # 
    # link:images/ipaccess_setup_origin_tab.png
    #
    # After calling this method you may find
    # a reference to two original objects.
    # First in a +cidr+'s tag and second
    # returned by the method. By converntion
    # you should rely more on returned value
    # since it may carry a real object (e.g.
    # Net::Something) whereas tag may point
    # to an underlying object that had been
    # used to fetch IP from (e.g. TCPSocket).
    # 
    # This method returns the originator or +nil+.
    
    def setup_originator(cidr, orig=nil, net_obj=nil)
      if orig.nil?
        if (cidr.respond_to?(:tag) && !cidr.tag[:Originator].nil?)
          orig = cidr.tag[:Originator]
        else
          unless net_obj.nil?
            orig = net_obj
            cidr.tag[:Originator] = orig
          end
        end
      elsif orig == :none
        orig = nil
      elsif (cidr.respond_to?(:tag) && cidr.tag[:Originator].nil?)
        cidr.tag[:Originator] = orig
      end
      
      return orig
    end
    private :setup_originator
    
    # This method checks IP access for
    # CIDR objects. If the access is denied it raises an exception
    # reporting first rejected IP. If the access is granted it
    # returns an array containing the given argument(s).
    #
    # +list+ should be an access list (a kind of IPAccess::List),
    # +exception+ should be an exception class that
    # will be used to raise an exception and +addresses+
    # should be a list of objects containing IP
    # addresses. See the description of IPAccess.to_cidrs
    # for more info about arguments you may pass.
    # 
    # This method will try to set up originators
    # for tested addresses. That's why it will pass
    # +:include_origins+ option to underlying methods
    # which use IPAccess.to_cidrs to fetch
    # IP addresses from many kinds of objects.
    # You may force originators to be set to
    # +orig+ if it's not +nil+.
    # 
    # === Workflow
    # 
    # In order to understand this method's logic
    # properly you may look at the diagram:
    # 
    # link:images/ipaccess_ac_for_args.png
    
    def check(list, exception=IPAccessDenied, orig=nil, *addresses) # :yields: address, rule, acl, addresses, orig
      return addresses if list.empty?
      addresses.push :include_origins
      pairs = list.denied(*addresses)
      unless pairs.empty?
        addr = pairs.first[:IP]
        rule = pairs.first[:Rule]
        orig = setup_originator(addr, orig)
        dont_scream = false
        dont_scream = yield(addr, rule, list, addresses, orig) if block_given?
        scream!(addr, rule, exception, orig) unless dont_scream
      end
      return addresses
    end
    protected :check
    
    # This method checks access for a socket.
    #  
    # It works the same way as check method but expects you
    # to give single Socket object instead of list of
    # arguments and an optional +orig+ object to be used
    # as an originator when raising an exception.
    # If the last argument is not given then the originator
    # will be set to tested object. To reset originator
    # pass +:none+ as the last argument.
    # In order to understand this method's logic
    # properly you may look at the diagram:
    # 
    # link:images/ipaccess_ac_for_socket.png
    
    def check_socket(list, exception, socket, orig=nil) # :yields: address, rule, acl, socket, orig
      if (list.empty? || !socket.respond_to?(:getpeername))
        return socket
      end
      begin
        peeraddr = Socket.unpack_sockaddr_in(socket.getpeername).last
      rescue IOError, Errno::ENOTCONN, Errno::ENOTSOCK, ArgumentError # socket is not INET, not a socket nor connected
        return socket
      end
      peer_ip = NetAddr::CIDR.create(peeraddr.split('%').first)
      pair    = list.denied_cidr(peer_ip, true)
      unless pair.empty?
        addr = pair[:IP]
        rule = pair[:Rule]
        orig  = setup_originator(addr, orig, socket)
        dont_scream = false
        dont_scream = yield(addr, rule, list, socket, orig) if block_given?
        scream!(addr, rule, exception, orig) unless dont_scream
      end
      return socket
    end
    protected :check_socket
    
    # This method checks access for a sockaddr.
    # It works the same way as check_socket but tests sockaddr structures.
    
    def check_sockaddr(list, exception, sockaddr, orig=nil) # :yields: address, rule, acl, sockaddr, orig
      return sockaddr if list.empty?
      begin
        peeraddr = Socket.unpack_sockaddr_in(sockaddr).last
      rescue ArgumentError # sockaddr is not INET
        return sockaddr
      end
      peer_ip = NetAddr::CIDR.create(peeraddr.split('%').first)
      pair    = list.denied_cidr(peer_ip, true)
      unless pair.empty?
        addr = pair[:IP]
        rule = pair[:Rule]
        orig  = setup_originator(addr, orig, sockaddr)
        dont_scream = false
        dont_scream = yield(addr, rule, list, sockaddr, orig) if block_given?
        scream!(addr, rule, exception, orig) unless dont_scream
      end
      return sockaddr
    end
    protected :check_sockaddr
    
    # This method checks access for a CIDR object.
    # It works the same way as check_socket but tests NetAddr::CIDR objects.
    
    def check_cidr(list, exception, cidr, orig=nil) # :yields: address, rule, acl, cidr, orig
      pair = list.denied_cidr(cidr, true)
      unless pair.empty?
        addr = pair[:IP]
        rule = pair[:Rule]
        orig  = setup_originator(addr, orig)
        dont_scream = false
        dont_scream = yield(addr, rule, list, cidr, orig) if block_given?
        scream!(addr, rule, exception, orig) unless dont_scream
      end
      return cidr
    end
    protected :check_cidr
    
    # This method checks access for a string containing
    # IP address. It works the same way as check_socket
    # but tests Strings containing IP addresses.
    
    def check_ipstring(list, exception, ipstring, orig=nil) # :yields: address, rule, acl, ipstring, orig
      return ipstring if list.empty?
      addr = NetAddr::CIDR.create(ipstring.split('%').first)
      pair = list.denied_cidr(addr, true)
      unless pair.empty?
        addr = pair[:IP]
        rule = pair[:Rule]
        orig  = setup_originator(addr, orig, ipstring)
        dont_scream = false
        dont_scream = yield(addr, rule, list, ipstring, orig) if block_given?
        scream!(addr, rule, exception, orig) unless dont_scream
      end
      return ipstring
    end
    protected :check_ipstring
    
    # This method checks IP access but bases on file descriptor.
    # It works the same way as check_socket but tests file descriptor.
    
    def check_fd(list, exception, fd, orig=nil, &block) # :yields: address, rule, access_list, socket, orig
      orig = fd if orig.nil?
      check_socket(list, exception, ::Socket.for_fd(fd), orig, &block)
      return fd
    end
    protected :check_fd
    
    # This method checks access for the given objects
    # containing IP addresses against input access list.
    # If the access for any of the given addresses is denied then
    # the IPAccessDenied::Input exception is raised for that
    # particular IP. If the access is granted this method
    # returns an array containing the given arguments.
    # 
    # === Tracking original network objects
    # 
    # Exception raises when some IP is denied.
    # That IP comes from one, particular object
    # passed as one of the arguments. This object
    # is passed as +originator+ attribute of the
    # exception.
    # That allows you to find the original network object
    # that had been checked, not just its internal
    # representation (+peer_ip+ attribute) that
    # is a kind of NetAddr::CIDR.
    # Be aware that NetAddr::CIDR objects passed
    # as arguments may also have
    # originators set inside (check <tt>tag[:Originator]</tt>).
    # In that case the originator is simply copied and not set to
    # any CIDR. Also remember that NetAddr::CIDR objects
    # are never set nor reported as originators.
    # In order to track originators the +:include_origin+
    # option is used when calling IPAccess.to_cidrs.
    # 
    # === Passing a block
    # 
    # Optional block may be passed to this method. It will
    # be called once, when the access for a remote IP
    # address turns out to be denied. If it will
    # evaluate to +true+ then no exception is raised,
    # even if the IP is not allowed to connect.
    # Remember to return +false+ or +nil+ in the block
    # to avoid random admissions. The block may take
    # the following arguments:
    # 
    # <br />
    # * +address+ of a denied IP (a kind of NetAddr::CIDR)
    # * +rule+ that matched (a kind of NetAddr::CIDR)
    # * +access_list+ pointing to a used access list (kind of IPAccess::List)
    # * +addresses+ containing an array of arguments (IP addresses)
    # * +orig+ indended to be placed as the +originator+ attribute in an exception
    # <br />
    # 
    # === Faster alternatives
    # 
    # This method is relatively easy to use but you may
    # also try more efficient access checking
    # methods if your object contains information about
    # single IP and is a known kind.
    # 
    # See the protected check method description for more
    # info about internals. See IPAccess.to_cidrs
    # description for more info about arguments you may
    # pass to this method.
    
    def check_in(*addresses, &block) # :yields: address, rule, access_list, addresses, orig
      check(@input, IPAccessDenied::Input, nil, *addresses, &block)
    end
    
    # This method acts the same way as check_in
    # but uses output access list and raises
    # the exception object called IPAccessDenied::Output.
    
    def check_out(*addresses, &block) # :yields: address, rule, access_list, addresses, orig
      check(@output, IPAccessDenied::Output, nil, *addresses, &block)
    end
        
    # This method checks access for the given NetAddr::CIDR
    # kind of object containing IP address against input access
    # list. If the access for the given address is denied then
    # the IPAccessDenied::Input exception is raised.
    # If the access is granted this method
    # returns the given +cidr+.
    # 
    # === Tracking original network objects
    # 
    # An exception is raised when access for some
    # IP is denied. That IP comes from given +cidr+ object
    # passed as first argument. This object's
    # <tt>tag[:Originator]</tt> is fetched and
    # passed as +originator+ attribute of an exception
    # which is kind of IPAccessDenied.
    # That step may be skipped if there is +orig+ argument
    # present. In such case the originator is taken
    # from it. That allows you to find the original
    # network object that had been checked while catching
    # the excetion.
    # 
    # Remember that NetAddr::CIDR objects
    # are never set nor reported as originators unless
    # you force them to be by passing as the
    # +orig+ argument.
    # 
    # === Passing a block
    # 
    # Optional block may be passed to this method. It will
    # be called once, when the access for a remote IP
    # address turns out to be denied. If it will
    # evaluate to +true+ then no exception is raised,
    # even if the IP is not allowed to connect.
    # Remember to return +false+ or +nil+ in the block
    # to avoid random admissions. The block may take
    # the following arguments:
    # 
    # <br />
    # * +address+ of a denied IP (a kind of NetAddr::CIDR)
    # * +rule+ that matched (a kind of NetAddr::CIDR)
    # * +access_list+ pointing to a used access list (kind of IPAccess::List)
    # * +addresses+ containing an array of arguments (IP addresses)
    # * +orig+ indended to be placed as the +originator+ attribute in an exception
    # <br />
    # 
    # See the protected check_cidr method description for more
    # info about internals. See IPAccess.to_cidrs
    # description for more info about arguments you may
    # pass to this method.
  
    def check_in_cidr(cidr, orig=nil, &block) # :yields: address, rule, access_list, cidr, orig
      check_cidr(@input, IPAccessDenied::Input, cidr, orig, &block)
    end
  
    # This method acts the same way as check_in_cidr
    # but uses output access list and raises
    # the exception object called IPAccessDenied::Output.
    
    def check_out_cidr(cidr, orig=nil, &block) # :yields: address, rule, access_list, cidr, orig
      check_cidr(@output, IPAccessDenied::Output, cidr, orig, &block)
    end
    
    # This method acts the same way as check_in_cidr
    # but the originator is set to the given string.
    # It may be overwritten if +orig+ argument is present.
    
    def check_in_ipstring(ipstring, orig=nil, &block) # :yields: address, rule, access_list, ipstring, orig
      check_ipstring(@input, IPAccessDenied::Input, ipstring, orig, &block)
    end
  
    # This method works the same way as check_in_ipstring
    # but uses output access list and raises IPAccessDenied::Output
    # exceptions.
    
    def check_out_ipstring(ipstring, orig=nil, &block) # :yields: address, rule, access_list, ipstring, orig
      check_ipstring(@output, IPAccessDenied::Output, ipstring, orig, &block)
    end
    
    # This method works the same way as check_in_ipstring
    # but tests socket.
    
    def check_in_socket(socket, orig=nil, &block) # :yields: address, rule, access_list, socket, orig
      check_socket(@input, IPAccessDenied::Input, socket, orig, &block)
    end
    
    # This method works the same way as check_in_socket
    # but uses output access list and raises IPAccessDenied::Output
    # exceptions.
    
    def check_out_socket(socket, orig=nil, &block) # :yields: address, rule, access_list, socket, orig
      check_socket(@output, IPAccessDenied::Output, socket, orig, &block)
    end
    
    # This method works the same way as check_in_ipstring
    # but tests sockaddr structure.
    
    def check_in_sockaddr(sockaddr, orig=nil, &block) # :yields: address, rule, access_list, sockaddr, orig
      check_sockaddr(@input, IPAccessDenied::Input, sockaddr, orig, &block)
    end
  
    # This method works the same way as check_in_sockaddr
    # but uses output access list and raises IPAccessDenied::Output
    # exceptions.
  
    def check_out_sockaddr(sockaddr, orig=nil, &block) # :yields: address, rule, access_list, sockaddr, orig
      check_sockaddr(@output, IPAccessDenied::Output, sockaddr, orig, &block)
    end
    
    # This method works the same way as check_in_ipstring
    # but tests file descriptor.
        
    def check_in_fd(fd, orig=nil, &block) # :yields: address, rule, access_list, fd, orig
      check_fd(@input, IPAccessDenied::Input, fd, orig, &block)
    end
    
    # This method works the same way as check_in_fd
    # but uses output access list and raises IPAccessDenied::Output
    # exceptions.
    
    def check_out_fd(fd, orig=nil, &block) # :yields: address, rule, access_list, fd, orig
      check_fd(@output, IPAccessDenied::Output, fd, orig, &block)
    end
    
    # This method shows access set in human readable form.
    
    def show(reasons=false)
      r = ""
      unless @input.empty?
        r = ".=========================================.\n"   +
            ". Rules for incoming traffic:\n\n"               +
            @input.show(reasons)
        r += "\n" if @output.empty?
      end
      unless @output.empty?
        r += "\n" unless @input.empty?
        r +=  ".=========================================.\n" +
              ". Rules for outgoing traffic:\n\n"             +
              @output.show(reasons) + "\n"
      end
      return r
    end
    
  end # class Set

end # module IPAccess

