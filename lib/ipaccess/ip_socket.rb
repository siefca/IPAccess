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

require 'socket'

# This class handles access denied exceptions.
 
class IPAccessDenied < Errno::EACCES; end

# This version of IPSocket class uses IPAccess to control
# incomming and outgoing connections.

module IPSocketAccess

  def initialize(*args)
    @in_access = nil
    @out_access = nil
    return super(*args)
  end

  def accept(*args)
    ret = super(*args)
    p "mam #{ret}"
    return ret
  end
end

IPSocket.send(:include, IPSocketAccess)

