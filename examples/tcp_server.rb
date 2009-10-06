$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/socket'

acl = IPAccess.new
acl.input.blacklist :strange

# 0

serv = IPAccess::TCPServer.new(31337)     # create listening TCP socket
serv.acl = :private                       # create and use private access set
serv.blacklist :local, :private           # block local and private IP addresses
serv.permit '127.0.0.5'                   # make an exception

puts serv.acl.show                        # show listed IP addresses
sock = serv.sysaccept                     # accept connection


# 1

# Create and use the TCP socket

s = IPAccess::TCPServer.new(31337, acl)
#s = TCPServer.new(31337)

# Arm object s
#IPAccess.arm s, acl

puts s.acl.show
g = s.accept


