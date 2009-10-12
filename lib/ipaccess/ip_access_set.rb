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
  # kind of IPAccessDenied. Each of these exceptions contain
  # IP address, rule that matched, diagnostic message
  # and an optional object that had been passed to any
  # of the access checking methods as their optional
  # argument.
  # 
  # ==== Accessing original object
  # 
  # The optional object mentioned before is intended to
  # be used as a helpful reference to original object for
  # which access is checked.
  # That allows you to use it while handling the exception;
  # e.g. send some data through the socket before closing it.
  # If this additional object is +nil+ or wasn't passed
  # to the access checking method, the method
  # will try to obtain it automagically. How?
  # It will try to fetch it from the +:Originator+ tag
  # of NetAddr::CIDR object that had been used. This tag
  # will be preset because the method will add +:inclulde_origins+
  # option while calling IPAccess.obj_to_cidr on a list of
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
      else
        cidr.tag[:Originator] = orig if (cidr.respond_to?(:tag) && cidr.tag[:Originator].nil?)
      end
      
      return orig
    end
    private :setup_originator
    
    # This method checks IP access of traffic for
    # CIDR objects. If access is denied it raises an exception
    # reporting first rejected IP. If access is granted it
    # returns an array containing the given argument(s).
    # See IPAccess::List.obj_to_cidr description for more info
    # about arguments you may pass to it.
    # 
    # === Workflow
    # 
    # In order to understand this method's logic
    # properly you may look at the diagram:
    # 
    # link:images/ipaccess_ac_for_args.png
    
    def check(list, exc, orig, *args) # :yields: address, rule, acl, args, orig
      return args if list.empty?
      pairs = list.denied(*args)
      unless pairs.empty?
        addr = pairs.first[:IP]
        rule = pairs.first[:Rule]
        orig  = setup_originator(addr, orig)
        dont_scream = false
        dont_scream = yield(addr, rule, list, args, orig) if block_given?
        scream!(addr, rule, exc, orig) unless dont_scream
      end
      return args
    end
    protected :check
    
    # This method checks access for a socket.
    #  
    # In order to understand this method's logic
    # properly you may look at the diagram:
    # 
    # link:images/ipaccess_ac_for_socket.png
    
    def check_socket(list, exc, socket, orig=nil) # :yields: address, rule, acl, socket, orig
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
        scream!(addr, rule, exc, orig) unless dont_scream
      end
      return socket
    end
    protected :check_socket
    
    # This method checks access for a sockaddr.
    
    def check_sockaddr(list, exc, sockaddr, orig=nil) # :yields: address, rule, acl, sockaddr, orig
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
        scream!(addr, rule, exc, orig) unless dont_scream
      end
      return sockaddr
    end
    protected :check_sockaddr
    
    # This method checks access for a CIDR object.
    
    def check_cidr(list, exc, cidr, orig=nil) # :yields: address, rule, acl, cidr, orig
      pair = list.denied_cidr(cidr, true)
      unless pair.empty?
        addr = pair[:IP]
        rule = pair[:Rule]
        orig  = setup_originator(addr, orig)
        dont_scream = false
        dont_scream = yield(addr, rule, list, cidr, orig) if block_given?
        scream!(addr, rule, exc, obj) unless dont_scream
      end
      return cidr
    end
    protected :check_cidr
    
    # This method checks access for a string containing
    # IP address.
    
    def check_ipstring(list, exc, ipstring, obj=nil) # :yields: address, rule, acl, ipstring, obj
      return ipstring if list.empty?
      addr = NetAddr::CIDR.create(ipstring.split('%').first)
      pair = list.denied_cidr(addr, true)
      unless pair.empty?
        addr = pair[:IP]
        rule = pair[:Rule]
        obj  = setup_originator(addr, obj, ipstring)
        dont_scream = false
        dont_scream = yield(addr, rule, list, ipstring, obj) if block_given?
        scream!(addr, rule, exc, obj) unless dont_scream
      end
      return ipstring
    end
    protected :check_ipstring
    
    # This method checks IP access but bases on file descriptor.
    
    def check_fd(list, exc, fd, obj=nil, &block) # :yields: address, rule, access_list, socket, object
      obj = fd if obj.nil?
      check_socket(list, exc, Socket.for_fd(fd), obj, &block)
      return fd
    end
    protected :check_fd
    
    # This method checks access for the given objects
    # (containing IP information) against input access list.
    # If the access for any address is denied then
    # the IPAccessDenied::Input exception is raised for that
    # one IP. If access is granted this method returns an array
    # containing the given arguments. First argument is an optional
    # object that will be passed to the exception raising
    # routine and then placed in an exception as the
    # +IPAccessDenied.originator+ attribute.
    # If access is granted it
    # returns an array containing the given argument(s).
    # 
    # === Tracking original network objects
    # 
    # If the first argument is +nil+ then
    # during raising the exception the original object
    # that IP address had been obtained from is
    # passed as +originator+ attribute of the
    # exception's object. That allows you to know
    # the original object that had been checked
    # when catching the exception. Be aware that
    # NetAddr::CIDR kind of objects that contain IP
    # addresses may also have the originator set inside (check
    # <tt>tag[:Originator]</tt>) and it will be
    # copied in case of that kind of objects.
    # If you want to set your own object as originator
    # but still would like address resolving routines
    # to mark any matching address with original object
    # that the IP had been fetched from, you may add
    # special symbol +:include_origins+ to the arguments'
    # list.
    # 
    # === Passing a block
    # 
    # Optional block may be passed to this method. It will
    # be called once, when the access for a remote IP
    # address turns out to be denied. If it will
    # evaluate to +true+ then no exception will be raised,
    # even if the IP is not allowed to connect.
    # Remember to return +false+ or +nil+ in the block
    # to avoid random admissions.
    # The block may take the following arguments:
    # 
    # * _address_ of the denied IP (kind of NetAddr::CIDR)
    # * _rule_ that matched (kind of NetAddr::CIDR)
    # * _access_list_ pointing to the used access list (kind of IPAccess::List)
    # * _args_ containing an array of arguments (IP addresses)
    # * _object_ indended to be placed as the +originator+ attribute in exception
    # 
    # === Faster alternatives
    # 
    # This method is relatively easy to use but you may
    # also try more efficient access checking
    # methods if your object contains information about
    # single IP and is a known kind.
    # 
    # See the protected check method description for more
    # info about internals. See IPAccess::List.obj_to_cidr
    # description for more info about arguments you may
    # pass to this method.
    
    def check_in(obj, *args, &block) # :yields: address, rule, access_list, args, object
      args.push :include_origins if obj.nil?
      check(@input, IPAccessDenied::Input, obj, *args, &block)
    end
    
    # This method acts the same way as check_in
    # but uses output access list and raises
    # the exception object called IPAccessDenied::Output.
    
    def check_out(obj, *args, &block) # :yields: address, rule, access_list, args, object
      args.push :include_origins if obj.nil?
      check(@output, IPAccessDenied::Output, obj, *args, &block)
    end
    
    # This method checks access for the given object
    # (containing IP information) against input access list.
    # Expected +cidr+ argument should be kind of NetAddr::CIDR
    # If the access for any address is denied then
    # the IPAccessDenied::Input exception is raised for that
    # one IP. If access is granted this method returns an array
    # containing the given arguments.
    #
    # Second, optional argument should be an
    # object that will be passed to the exception raising
    # routine and then placed in an exception as the
    # +IPAccessDenied.originator+ attribute.
    # See IPAccess::List.obj_to_cidr description for more info
    # about arguments you may pass to this method.
    
    # This method calls check_in using an input list.
  
    def check_in_cidr(cidr, obj=nil, &block) # :yields: address, rule, access_list, cidr, object
      check_cidr(@input, IPAccessDenied::Input, cidr, obj, &block)
    end
  
    # This method checks access for the given CIDR object
    # (containing IP information) against output access list.
    # If access is denied it raises an exception reporting
    # a pair of values (rejected IP and a matching rule).
    # If access is granted it returns the given argument.
    # 
    # Expected argument should be kind of NetAddr::CIDR.
    
    def check_out_cidr(cidr, obj=nil, &block) # :yields: address, rule, access_list, cidr, object
      check_cidr(@output, IPAccessDenied::Output, cidr, obj, &block)
    end
    
    # This method checks access for the given string
    # (containing IP information) against input access list.
    # If access is denied it raises an exception reporting
    # a pair of values (rejected IP and a matching rule).
    # If access is granted it returns the given argument.
    
    def check_in_ipstring(ipstring, obj=nil, &block) # :yields: address, rule, access_list, ipstring, object
      check_ipstring(@input, IPAccessDenied::Input, ipstring, obj, &block)
    end
  
    # This method checks access for the given string
    # (containing IP information) against output access list.
    # If access is denied it raises an exception reporting
    # a pair of values (rejected IP and a matching rule).
    # If access is granted it returns the given argument.
    
    def check_out_ipstring(ipstring, obj=nil, &block) # :yields: address, rule, access_list, ipstring, object
      check_ipstring(@output, IPAccessDenied::Output, ipstring, obj, &block)
    end
    
    # This method checks access for the given socket object
    # (containing IP information) against input access list.
    # If access is denied it raises an exception reporting
    # a pair of values (rejected IP and a matching rule).
    # If access is granted it returns the given argument.
    # 
    # Expected argument should be kind of IPSocket. See
    # description of the protected method check_socket
    # for more info about internals.
    
    def check_in_socket(socket, obj=nil, &block) # :yields: address, rule, access_list, socket, object
      check_socket(@input, IPAccessDenied::Input, socket, obj, &block)
    end
    
    # This method checks access for the given socket object
    # (containing IP information) against output access list.
    # If access is denied it raises an exception reporting
    # a pair of values (rejected IP and a matching rule).
    # If access is granted it returns the given argument.
    # 
    # Expected argument should be kind of IPSocket.
    
    def check_out_socket(socket, obj=nil, &block) # :yields: address, rule, access_list, socket, object
      check_socket(@output, IPAccessDenied::Output, socket, obj, &block)
    end
    
    # This method checks access for the given sockaddr structure
    # (containing IP information) against input access list.
    # If access is denied it raises an exception reporting
    # a pair of values (rejected IP and a matching rule).
    # If access is granted it returns the given argument.
    
    def check_in_sockaddr(sockaddr, obj=nil, &block) # :yields: address, rule, access_list, sockaddr, object
      check_sockaddr(@input, IPAccessDenied::Input, sockaddr, obj, &block)
    end
  
    # This method checks access for the given sockaddr structure
    # (containing IP information) against output access list.
    # If access is denied it raises an exception reporting
    # rejected IP and a matching rule. If access is granted
    # it returns the given argument.
    
    def check_out_sockaddr(sockaddr, obj=nil, &block) # :yields: address, rule, access_list, sockaddr, object
      check_sockaddr(@output, IPAccessDenied::Output, sockaddr, obj, &block)
    end
    
    # This method checks access for the given file descriptor
    # (containing IP information) against input access list.
    # If access is denied it raises an exception reporting
    # a pair of values (rejected IP and a matching rule).
    # If access is granted it returns the given argument.
    # 
    # Expected argument should be a number representing a valid
    # file descriptor bound to an IP socket.
        
    def check_in_fd(fd, obj=nil, &block) # :yields: address, rule, access_list, fd, object
      check_fd(@input, IPAccessDenied::Input, fd, obj, &block)
    end
  
    # This method checks access for the given file descriptor
    # (containing IP information) against output access list.
    # If access is denied it raises an exception reporting
    # a pair of values (rejected IP and a matching rule).
    # If access is granted it returns the given argument.
    # 
    # Expected argument should be a number representing a valid
    # file descriptor bound to an IP socket.
    
    def check_out_fd(fd, obj=nil, &block) # :yields: address, rule, access_list, fd, object
      check_fd(@output, IPAccessDenied::Output, fd, obj, &block)
    end
    
    # This method shows access set in human readable form.
    
    def show
      r = ""
      unless @input.empty?
        r = ".=========================================.\n"   +
            ". Rules for incoming traffic:\n\n"               +
            @input.show
        r += "\n" if @output.empty?
      end
      unless @output.empty?
        r += "\n" unless @input.empty?
        r +=  ".=========================================.\n" +
              ". Rules for outgoing traffic:\n\n"             +
              @output.show + "\n"
      end
      return r
    end
    
  end # class Set

end # module IPAccess

