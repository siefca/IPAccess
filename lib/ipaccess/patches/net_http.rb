# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Modules contained in this file are meant for
# patching Ruby Net::HTTP classe in order to add
# IP access control to  it. It is also used
# to create variant of Net::HTTP class
# with IP access control.
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
# 

require 'net/http'
require 'ipaccess/ip_access_errors'
require 'ipaccess/patches/generic'

# :stopdoc:

# This modules contain patches for Ruby socket
# classes in order to enable IP access control
# for them.
#
# This module patches socket handling classes
# to use IP access control. Each patched socket
# class has acl member, which is an IPAccess object.

module IPAccess::Patches
  
  
  
end # module IPAccess::Patches

# :startdoc:

