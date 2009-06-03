# encoding: utf-8
# 
# == Simple and handy IP access control.
#
# Author::    Paweł Wilk (mailto:pw@gnu.org)
# Copyright:: Copyright (c) 2009 Paweł Wilk
# License::   This program is licensed under the terms of {GNU Lesser General Public License}[link:LGPL-LICENSE.html] or Ruby License.
# 
# === ghost_doc
# 
# Classes contained are just for documentary purposes.
# It is a scaffold for keeping virtual methods that
# cannot be detected by RDoc.

class IPAccess::Socket
  # This method selects IPAccess object that will be used to
  # control IP access for a socket. You may assign global access set,
  # create local access set or use shared set.
  # 
  # If argument is an IPAccess object then it is used.
  # If argument is other kind it is assumed that it
  # should be converted to IPAccess object (initial arguments
  # are considered to be IP rules for a black list). If argument
  # is +:global+ it uses global access set. If argument is +:private+
  # it creates an empty, private access set.
  # 
  # ==== Example
  #
  #     socket.acl = :global        # use global access set
  #     socket.acl = :private       # create and use individual access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=(set); end
  
  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  attr_reader :acl

end

class IPAccess::UDPSocket
  # This method selects IPAccess object that will be used to
  # control IP access for a socket. You may assign global access set,
  # create local access set or use shared set.
  # 
  # If argument is an IPAccess object then it is used.
  # If argument is other kind it is assumed that it
  # should be converted to IPAccess object (initial arguments
  # are considered to be IP rules for a black list). If argument
  # is +:global+ it uses global access set. If argument is +:private+
  # it creates an empty, private access set.
  # 
  # ==== Example
  #
  #     socket.acl = :global        # use global access set
  #     socket.acl = :private       # create and use individual access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=(set); end
  
  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  attr_reader :acl

end

class IPAccess::SOCKSSocket
  # This method selects IPAccess object that will be used to
  # control IP access for a socket. You may assign global access set,
  # create local access set or use shared set.
  # 
  # If argument is an IPAccess object then it is used.
  # If argument is other kind it is assumed that it
  # should be converted to IPAccess object (initial arguments
  # are considered to be IP rules for a black list). If argument
  # is +:global+ it uses global access set. If argument is +:private+
  # it creates an empty, private access set.
  # 
  # ==== Example
  #
  #     socket.acl = :global        # use global access set
  #     socket.acl = :private       # create and use individual access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=(set); end

  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  attr_reader :acl

end

class IPAccess::TCPSocket
  # This method selects IPAccess object that will be used to
  # control IP access for a socket. You may assign global access set,
  # create local access set or use shared set.
  # 
  # If argument is an IPAccess object then it is used.
  # If argument is other kind it is assumed that it
  # should be converted to IPAccess object (initial arguments
  # are considered to be IP rules for a black list). If argument
  # is +:global+ it uses global access set. If argument is +:private+
  # it creates an empty, private access set.
  # 
  # ==== Example
  #
  #     socket.acl = :global        # use global access set
  #     socket.acl = :private       # create and use individual access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=(set); end
  
  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  attr_reader :acl
  
end

class IPAccess::TCPServer
  # This method selects IPAccess object that will be used to
  # control IP access for a socket. You may assign global access set,
  # create local access set or use shared set.
  # 
  # If argument is an IPAccess object then it is used.
  # If argument is other kind it is assumed that it
  # should be converted to IPAccess object (initial arguments
  # are considered to be IP rules for a black list). If argument
  # is +:global+ it uses global access set. If argument is +:private+
  # it creates an empty, private access set.
  # 
  # ==== Example
  #
  #     socket.acl = :global        # use global access set
  #     socket.acl = :private       # create and use individual access set
  #     socket.acl = IPAccess.new   # use external (shared) access set
  def acl=(set); end
  
  # This member allows you to manipulate local and shared access sets
  # associated with this socket. To control global access set use
  # IPAccess::Global
  attr_reader :acl
  
end

