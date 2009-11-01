# encoding: utf-8
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:docs/LGPL-LICENSE.html] or {Ruby License}[link:docs/COPYING.html].
# 
# Classes contained in this file are subclasses
# of Ruby's POP3 handling classes equipped
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
# 
# See ipaccess/ghost_doc/ghost_doc.rb for documentation of this classes.
# 
#++

require 'net/pop'
require 'ipaccess/ip_access_set'
require 'ipaccess/patches/net_pop'


module IPAccess::Net
  
  class POP3 < Net::POP3
    include IPAccess::Patches::Net::POP3
  end
  
  class APOP < IPAccess::Net::POP3
    # Always returns true.
    def apop?
      true
    end
  end
  
end

