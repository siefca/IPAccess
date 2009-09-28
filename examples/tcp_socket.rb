$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/socket'

# Add host's IP by to black list of global output access set
IPAccess::Global.output.blacklist 'randomseed.pl'

# Create and use the TCP socket
s = TCPSocket.new('randomseed.pl', 80)

# Arm object s
IPAccess.arm s

