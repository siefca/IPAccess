$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/socket'

# Add host's IP by to black list of global output access set
IPAccess::Global.output.blacklist 'randomseed.pl'

# Arm TCPSocket class of Ruby
IPAccess.arm TCPSocket

# Create and use the TCP socket
s = TCPSocket.new('randomseed.pl', 80)

