# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009-2014 by Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL.html] or {Ruby License}[link:docs/COPYING.html].
# 
# This file contains IPAccess::List::Check class, which
# extends IPAccess::List class by adding exceptions and
# checks.
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
require 'ipaccess/ip_access_errors'
require 'ipaccess/ip_access_list'

module IPAccess
  
  # This class maintains a simple access list
  # containing rules and methods for checking
  # access.
  # 
  # ==== Rules management
  # 
  # Use instance methods to add or remove
  # rules from the list. Both IPv4 and IPv6 addresses
  # are supported. See IPAccess.cidrs for available
  # formats of addresses.
  # 
  # ==== Checking access
  # 
  # To check an access you may call methods that belong
  # to this list.
  # 
  # There are different variants of this methods
  # for different IP representations. That's because
  # speed is important here. If you have a socket object
  # you want to test then you should use a method that
  # checks sockets. If your IP is in a text format you
  # may want to use a method that checks IP addresses
  # written as strings.
  # 
  # ==== Exceptions
  # 
  # Access checking methods throw exceptions that are
  # kind of IPAccessDenied or derivative. You may also set
  # the exception class using +exception+ attribute
  # of instances. Each exception contain
  # IP address, rule that matched, diagnostic message
  # and an optional object that points to so
  # called originator described below. See IPAccessDenied
  # to see all attributes present in an exception.
  # 
  # ==== Accessing original object
  # 
  # You can pass an optional object to almost all
  # of the access checking methods. It usually will be
  # passed as the last argument called +originator+.
  # The originator is intended to be used as a
  # helpful reference to original object for which an
  # access is checked.
  # 
  # You may want to ask why there is a need for
  # originator when some object is tested already.
  # The problem is that not just sockets can raise
  # exceptions. If you want your program to block
  # access before socket is even created (for outgoing
  # traffic) then you may validate IP earlier.
  # There are also some situations when you want to test
  # something that represents network object's IP
  # but it's not related to network object itself.
  # For example, imagine that your program creates
  # objects for HTTP sessions. In your HTTP class
  # you may add some access checks but the tested
  # object will be a socket. In that case you may want
  # to pass HTTP object to an access checking method
  # as the originator while performing access check on
  # a socket.
  # 
  # Originator is transported within an exception
  # so you can use it in rescue section to send some data
  # or do other stuff before closing network
  # object. In case of patched network objects and
  # special variants of network classes that
  # this library also provides, you may also find
  # +:opened_on_deny+ option helpful to achieve that.
  # 
  # In case of general purpose method like check
  # you cannot pass the originator because it uses
  # variant list of arguments of different kinds –
  # in that case however the originators will be established
  # using original, checked objects. The only disadvantage
  # is that you cannot set the originators manually.
  # 
  # If the additional argument +originator+ is +nil+
  # or is not passed to the access checking method, the method
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
  # for testing.
  # 
  # Access checking methods will try to fill up missing
  # +:Originator+ tag in each processed object containing
  # IP address while figuring out the original object.
  # By object containing IP address we mean NetAddr::CIDR
  # kind of object that is used by underlying routines to
  # check access and reported during exception raising
  # as +peer_ip+ attribute. Checking methods will use private
  # method setup_originator to decide which object should
  # be choosen as the originator.
    
  class List::Check < List
    
    # This attribute contains default
    # exception that this class should throw
    # when an access is denied. It must be
    # a kind of IPAccessDenied or derivative.

    attr_accessor :exception
  
    # Creates new IPAccess::List::Ch object. You may pass objects
    # (containing IP information) to it. These objects will
    # create black list rules. See IPAccess.to_cidrs description
    # for more info on how to pass arguments.
    # 
    # IPAccess::List::Check object and/or NetAddr::CIDR object(s) may
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
    #     IPAccess::List::Check.new '192.168.0.0/16', '127.0.0.1/255.0.0.0'
    #     IPAccess::List::Check.new :private, :local
    #     IPAccess::List::Check.new "randomseed.pl", :nonpublic
    
    def initialize(*addresses)
      @exception = IPAccessDenied
      super(*addresses)
    end

    # This is core adding method.
    
    def add_core(reason, *addresses)
      added = super(reason, *addresses)
      return added
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
    
    def delete!(*addresses)
      removed = super(*addresses)
      return removed
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
    
    # Raises default exception including important informations like
    # remote IP address, rule that IP matched to, used access list
    # and optional object passed as an argument.
    # 
    # First argument (+addr+) should be a testet IP address in CIDR object and second 
    # argument (+rule+) of the same kind should contain a matching rule.
    # Third argument should be an exception class that will be used
    # to raise an exception. The last +originator+argument should be
    # an object that will be stored within the exception's object
    # as +originator+. It's recommended for it to be an object that
    # was used for communication and therefore tested but not a socket.
    # An underlying socket that caused an exception should be given as +socket+
    # if the object is not direct cause of the exception but the socket is.
    # In case of raw socket objects +socket+ should be the same as +originator+.
    
    def scream!(addr, rule, use_exception=IPAccessDenied, originator=nil, socket=nil)
      raise use_exception.new(addr, rule, self, originator, socket)
    end
    
    # This method checks IP access for
    # CIDR objects. If the access is denied it raises an exception
    # reporting first rejected IP. The exception class is taken from
    # a +exception+ attribute of this object – it should be IPAccessDenied
    # or derivative kind of object.
    #
    # If the access is granted it
    # returns an array containing the given argument(s).
    # 
    # The argument called +addresses+
    # should be a list of objects containing IP
    # addresses. See the description of IPAccess.to_cidrs
    # for more info about arguments you may pass.
    # 
    # This method will try to set up originators
    # for tested addresses. That's why it will pass
    # +:include_origins+ option to underlying methods
    # which use IPAccess.to_cidrs to fetch
    # IP addresses from many kinds of objects.
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
    # In that case the originator is simply copied.
    # Also remember that NetAddr::CIDR objects
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
    # * +access_list+ pointing to a used access list (this object)
    # * +addresses+ containing an array of arguments (IP addresses)
    # * +originator+ indended to be placed as the +originator+ attribute in an exception
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
    # 
    # === Workflow
    # 
    # In order to understand this method's logic
    # properly you may look at the diagram:
    # 
    # link:images/ipaccess_ac_for_args.png
    
    def check(*addresses) # :yields: address, rule, list, addresses, originator
      return addresses if self.empty?
      addresses.push :include_origins
      pairs = self.denied(*addresses)
      unless pairs.empty?
        addr = pairs.first[:IP]
        rule = pairs.first[:Rule]
        originator  = setup_originator(addr, originator)
        dont_scream = false
        dont_scream = yield(addr, rule, self, addresses, originator) if block_given?
        scream!(addr, rule, @exception, originator, nil) unless dont_scream
      end
      return addresses
    end
  
    # This method checks access for a socket.
    #  
    # It works the same way as the check method but expects you
    # to give a single Socket object instead of a list of
    # arguments and an optional +originator+ object to be used
    # as an originator when raising an exception.
    # If the last argument is not given then the originator
    # will be set to tested object. To reset originator
    # pass +:none+ as the last argument.
    # In order to understand this method's logic
    # properly you may look at the diagram:
    # 
    # link:images/ipaccess_ac_for_socket.png
    
    def check_socket(socket, originator=nil) # :yields: address, rule, list, socket, originator
      if (self.empty? || !socket.respond_to?(:getpeername))
        return socket
      end
      begin
        peeraddr = Socket.unpack_sockaddr_in(socket.getpeername).last
      rescue IOError, Errno::ENOTCONN, Errno::ENOTSOCK, ArgumentError # socket is not INET, not a socket nor connected
        return socket
      end
      peer_ip = NetAddr::CIDR.create(peeraddr.split('%').first)
      pair    = self.denied_cidr(peer_ip, true)
      unless pair.empty?
        addr = pair[:IP]
        rule = pair[:Rule]
        originator  = setup_originator(addr, originator, socket)
        dont_scream = false
        dont_scream = yield(addr, rule, self, socket, originator) if block_given?
        scream!(addr, rule, @exception, originator, socket) unless dont_scream
      end
      return socket
    end
    protected :check_socket
    
    # This method checks access for a sockaddr.
    # It works the same way as check_socket but tests sockaddr structures.
    
    def check_sockaddr(sockaddr, originator=nil) # :yields: address, rule, list, sockaddr, orig
      return sockaddr if self.empty?
      begin
        peeraddr = Socket.unpack_sockaddr_in(sockaddr).last
      rescue ArgumentError # sockaddr is not INET
        return sockaddr
      end
      peer_ip = NetAddr::CIDR.create(peeraddr.split('%').first)
      pair    = self.denied_cidr(peer_ip, true)
      unless pair.empty?
        addr = pair[:IP]
        rule = pair[:Rule]
        originator  = setup_originator(addr, originator, sockaddr)
        dont_scream = false
        dont_scream = yield(addr, rule, self, sockaddr, originator) if block_given?
        scream!(addr, rule, @exception, originator, nil) unless dont_scream
      end
      return sockaddr
    end
    protected :check_sockaddr
    
    # This method checks access for a CIDR object.
    # It works the same way as check_socket but tests NetAddr::CIDR objects.
    
    def check_cidr(cidr, originator=nil) # :yields: address, rule, list, cidr, originator
      pair = self.denied_cidr(cidr, true)
      unless pair.empty?
        addr = pair[:IP]
        rule = pair[:Rule]
        originator  = setup_originator(addr, originator)
        dont_scream = false
        dont_scream = yield(addr, rule, self, cidr, originator) if block_given?
        scream!(addr, rule, @exception, originator, nil) unless dont_scream
      end
      return cidr
    end
    protected :check_cidr
    
    # This method checks access for a string containing
    # IP address. It works the same way as check_socket
    # but tests Strings containing IP addresses.
    
    def check_ipstring(ipstring, originator=nil) # :yields: address, rule, list, ipstring, originator
      return ipstring if self.empty?
      addr = NetAddr::CIDR.create(ipstring.split('%').first)
      pair = self.denied_cidr(addr, true)
      unless pair.empty?
        addr = pair[:IP]
        rule = pair[:Rule]
        originator  = setup_originator(addr, originator, ipstring)
        dont_scream = false
        dont_scream = yield(addr, rule, self, ipstring, originator) if block_given?
        scream!(addr, rule, @exception, originator, nil) unless dont_scream
      end
      return ipstring
    end
    protected :check_ipstring
    
    # This method checks IP access but bases on file descriptor.
    # It works the same way as check_socket but tests file descriptor.
    
    def check_fd(fd, originator=nil, &block) # :yields: address, rule, access_list, socket, originator
      originator = fd if originator.nil?
      check_socket(::Socket.for_fd(fd), originator, &block)
      return fd
    end
    protected :check_fd
  
  end # class List::Check
  
end # module IPAccess

