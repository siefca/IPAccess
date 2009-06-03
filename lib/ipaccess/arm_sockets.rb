# encoding: utf-8
#
# Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This is licensed under LGPL or Ruby License.
# 
# === arm_sockets
# 
# By requiring this file you are able to
# enable IP access control in standard
# Ruby sockets.

require 'socket'
require 'ipaccess/ip_access'
require 'ipaccess/ip_access_patches'

IPAccess.arm Socket
IPAccess.arm UDPSocket
IPAccess.arm TCPSocket
IPAccess.arm TCPServer
IPAccess.arm SOCKSSocket if Object.const_defined?(:SOCKSSocket)

