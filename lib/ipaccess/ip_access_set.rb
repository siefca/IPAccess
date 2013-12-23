# encoding: utf-8
# 
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# This file contains IPAccess::Set class, which uses
# IPAccess::List::Check objects to implement IP input/output
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
require 'ipaccess/ip_access_check'
require 'ipaccess/ip_access_errors'

module IPAccess
    
  # This class maintains an access set.
  # 
  # Objects of IPAccess::Set class, called <b>access sets</b>,
  # contain two access lists which are available
  # as accessible attributes: +input+ and +output+.
  # 
  # ==== Usage examples
  # 
  #   access = IPAccess::Set.new 'myset'    # create an access set
  #   access.input.block :private           # input list: block private subnets
  #   access.input.permit '192.168.1.1'     # input list: but permit 192.168.1.1 
  #   access.input.check '192.168.1.1'      # should pass
  #   access.input.check '192.168.1.2'      # should raise an exception
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
    
    # Access list for incoming IP traffic. See IPAccess::List::Check class
    # for more information on how to manage it.
    
    attr_reader   :input
    
    alias_method  :in, :input
    alias_method  :incoming, :input
    
    # Access list for outgoing IP traffic. See IPAccess::List::Check class
    # for more information on how to manage it.
    
    attr_reader   :output
    
    alias_method  :out, :output
    alias_method  :outgoing, :output
    
    # Descriptive name of this object. Used in error reporting.
    
    attr_accessor :name

    # This method creates new IPAccess::Set object. It optionally takes
    # two IPAccess::List::Check objects (initial data for access lists)
    # and descriptive name of an access set used in error reporting.
    # If there is only one argument it's assumed that it contains
    # descriptive name of an access set.
    
    def initialize(input=nil, output=nil, name=nil) 
      @name = nil
      @name, input = input, nil if (output.nil? && name.nil?)
      @input  = IPAccess::List::Check.new(input)
      @output = IPAccess::List::Check.new(output)
      @input.exception = IPAccessDenied::Input
      @output.exception = IPAccessDenied::Output
      return self
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
          @output = IPAccess::List::Check.new @input
        end
      end
      return nil
    end
    
    # This method shows an access set in a human readable form.
    
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

