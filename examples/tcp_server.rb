$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/socket'

acl = IPAccess.new
acl.input.blacklist :strange

# 1

# Create and use the TCP socket

s = IPAccess::TCPServer.new(31337, acl)
#s = TCPServer.new(31337)

# Arm object s
#IPAccess.arm s, acl

puts s.acl.show
g = s.accept


