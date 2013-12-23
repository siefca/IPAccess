# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009-2014 by Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Classes contained in this library allow you to create
# and manage IP access lists in an easy way. You may use
# IPAccess::Set class to maintain inpu/output traffic control.
# You also may use IPAccess::List class directly to build
# your own access sets based on black lists and white lists.

require 'ipaccess/patches/netaddr'
require 'ipaccess/ip_access_list'
require 'ipaccess/ip_access_set'

# This module contains classes that are
# used to control IP access. There are
# three major components you may need:
# 
# === IPAccess::List class
# 
# This class lets you create IP
# access list with blacklisted
# and whitelisted elements. It
# also has methods for checking
# whether given IP matches the
# list.
# 
# === IPAccess::Set class
# 
# This class contains two
# objects that are instances
# of IPAccess::List class.
# It allows you to create so
# called access set. The access
# set contains members named
# +input+ and +output+. All methods
# that validate IP access do it
# against one of the lists. Input
# access list is for incomming
# and output for outgoing IP traffic.
# In case of connection-oriented
# sockets and other network objects
# the convention is to use output access
# list to validate connections that
# we initiate. The incomming traffic
# in that model means the connections
# initiated by a remote peer.
# 
# === Patching engine
# 
# IPAccess was initialy considered as a
# set of classes that you may use
# in your own programs to control
# IP access. That means your own classes
# used for communication should use
# access lists or sets before making any
# real connections or sending any datagrams.
# 
# Fortunately there are many network classes,
# including sockets, that Ruby ships with.
# It would be waste of resources to not modify
# them to support IP access control and automagically
# throw exceptions when access should be denied.
# 
# And here the special module method called +IPAccess.arm+
# comes in. It lets you patch most of Ruby's
# networking classes and objects. Besides
# equipping them in IPAccess::Set instance
# it also adds some methods for doing quick
# checks and changes in access lists.
# 
# The patching engine can arm network classes and
# single network objects. It is not loaded by default
# since you may not want extra code attached to a
# program that uses access lists or sets with
# own access checking code.
# 
# === Variants of popular classes
# 
# Sometimes you want to write a code that
# uses standard Ruby's network objects
# but you find it dirty to alter classes or objects.
# In that case you may want to use static variants
# of Ruby's network classes that are not patches
# but derived classes.
# 
# === Exceptions
# 
# When you are dealing with patched (armed) versions
# of classes and objects or when you are using
# special variants of popular network classes, you have
# to rely on exceptions as the only way for
# access checking methods to tell your program
# that an event (like access denied) happened.
# 
# Note that when exception is thrown
# the communication session is closed in case
# of connection-oriented network objects.
# You may change it by switching +opened_on_deny+
# attribute to +true+.
# 
# See IPAccess::Set#check_in to know more
# about tracking original network object
# that caused exception to happend. Note
# that in case of armed versions of network
# classes (or access-contolled variants)
# an information about original network
# object stored within an exception will be set to
# +nil+ if access had been denied before
# object was initialized. This shouldn't
# happend often, since access checks are lazy
# (they are performed only when connection
# is going to be made).
# 
# See IPAccessDenied for more information
# about what you can do with exceptions.
# 
# === Sockets in armed network objects
# 
# Specialized Ruby's network classes,
# such as Net::HTTP or Net::Telnet
# and their variants created by this library,
# make use of socket objects. For example
# Net::HTTP class uses TCPSocket instance to
# create TCP connection. When versions
# of these <tt>Net::</tt> objects with
# enabled access control are used then
# the internal routines of IPAccess
# will also try to patch underlying sockets and assign
# to them the same access set that is used by main
# object. It is done to avoid access leaks.
# However, such armed internal sockets will have
# +opened_on_deny+ flag switched on since
# closing session (and an eventual connection)
# should be settled by main object.
# 
# === Ordination of elements
# 
# To properly understand what are the most important
# structures mentioned above it's worth
# to look at the diagram:
# 
# link:images/ipaccess_view.png
#  
# == Usage
# 
# === Handling access sets and access lists
# 
# If you need just IP access lists that you will handle in your own way
# you may want to use two classes:
# 
# * IPAccess::Set to maintain access sets (containing input and output access lists),
# * IPAccess::List to maintain single access list.
# 
# === Using socket classes
# 
# If you want standard sockets to have access control enabled
# you may want to use:
# 
# * IPAccess::Socket (or issue <tt>IPAccess.arm Socket</tt>)
# * IPAccess::TCPSocket (or issue <tt>IPAccess.arm TCPSocket</tt>)
# * IPAccess::UDPSocket (or issue <tt>IPAccess.arm UDPSocket</tt>)
# * IPAccess::SOCKSocket (or issue <tt>IPAccess.arm SOCKSocket</tt>)
# * IPAccess::TCPServer (or issue <tt>IPAccess.arm TCPServer</tt>)
# 
# Before using any of them you must issue:
# 
# * <tt>require 'ipaccess/socket'</tt>
# 
# Using the IPAccess.arm causes standard socket class to be altered,
# while \IPAccess:: classes are just new variants of socket
# handling classes.
# 
# ==== Using other supported network classes
# 
# If you want some working objects to have access control enabled
# you may want to use:
# 
# * IPAccess::Net::Telnet (or issue <tt>IPAccess.arm Net::Telnet</tt>)
# * IPAccess::Net::HTTP (or issue <tt>IPAccess.arm Net::HTTP</tt>)
# * IPAccess::Net::FTP (or issue <tt>IPAccess.arm Net::FTP</tt>)
# * IPAccess::Net::POP3 (or issue <tt>IPAccess.arm Net::POP3</tt>)
# * IPAccess::Net::IMAP (or issue <tt>IPAccess.arm Net::IMAP</tt>)
# * IPAccess::Net::SMTP (or issue <tt>IPAccess.arm Net::SMTP</tt>)
# 
# ==== Using single network objects
# 
# If you want to enable access control for single network
# object from the list shown above you may issue:
# 
# 	require 'ipaccess/net/http'
# 	obj = Net::HTTP.new(host, port)
# 	IPAccess.arm obj
# 
# or
# 
# 	require 'ipaccess/socket'
# 	socket = IPAccess::TCPServer.new(31337)
# 	IPAccess.arm socket
# 	
# ..and so on.
# 
# === Structures
# 
# IP addresses used by the classes are internaly and interfacialy
# represented by NetAddr::CIDR[http://netaddr.rubyforge.org/classes/NetAddr/CIDR.html]
# objects (NetAddr::CIDRv4[http://netaddr.rubyforge.org/classes/NetAddr/CIDRv4.html] and
# NetAddr::CIDRv6[http://netaddr.rubyforge.org/classes/NetAddr/CIDRv6.html]). Due to
# performance reasons any access list internally is represented as a tree
# (slightly modified NetAddr::Tree[http://netaddr.rubyforge.org/classes/NetAddr/Tree.html])
# with special tags assigning rules to virtual lists.
# 
# === Relations
# 
# Here is a diagram which shows relations
# between the IPAccess::TCPSocket class
# and other classes from this module:
# 
# link:images/ipaccess_relations.png

module IPAccess

  # This method converts names to NetAddr::CIDR objects. It returns an array of CIDR objects.
  # 
  # Allowed input are strings (DNS names or IP addresses optionally with masks), numbers (IP addresses representation),
  # IPSocket objects, URI objects, IPAddr objects, Net::HTTP objects, IPAddrList objects, NetAddr::CIDR objects,
  # NetAddr::Tree objects, IPAccess::List objects, symbols, objects that contain file descriptors bound to sockets
  # (including OpenSSL sockets) and arrays of these.
  #
  # In case of resolving the IPv6 link-local addresses
  # zone index is removed. In case of DNS names there may
  # occur Resolv::ResolvError exception. If there is an
  # object that cannot be converted the ArgumentError
  # exception is raised.
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
  
  def self.to_cidrs(*addresses)
    obj = addresses.flatten
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
    return obj.to_a if obj.is_a?(IPAccess::List)
  
    # NetAddr::Tree - immediate generation
    return obj.dump.map { |addr| addr[:CIDR] } if obj.is_a?(NetAddr::Tree)
  
    # number or nil - immediate generation or exception
    if (obj.is_a?(Numeric) || obj.nil?)
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
    obj = ::Socket.for_fd(obj.fileno) if (!obj.respond_to?(:getpeername) && obj.respond_to?(:fileno))
    
    # Socket - immediate generation
    if obj.respond_to?(:getpeername)
      peeraddr = ::Socket.unpack_sockaddr_in(obj.getpeername).last.split('%').first
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
          raise Resolv::ResolvError, "not connected or network error"
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
      return [r]
    end
    
    # should never happend
    r = obj.is_a?(NetAddr::CIDR) ? obj.dup : NetAddr::CIDR.create(obj.to_s)
    r.tag[:Originator] = ori_obj
    return [r]
  end
  
  # This method calls IPAccess.to_cidrs
  # and returns first obtained entry containing
  # single IP address with mask (NetAddr::CIDR).
  
  def self.to_cidr(*addresses)
    r = self.to_cidrs(*addresses)
    return r.respond_to?(:first) ? first : r
  end
  
end
