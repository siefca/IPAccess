$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/telnet'

acl = IPAccess.new

# Add host's IP by to black list
acl.output.blacklist 'localhost'

# Arm Net::Telnet class of Ruby
#IPAccess.arm Net::Telnet

opts = {}
opts["Host"] = 'randomseed.pl'
opts["Port"] = '80'
opts["ACL"] = acl

# Try to connect to remote host
t = IPAccess::Net::Telnet.new(opts)

# add new rule and check again
acl.output.blacklist 'randomseed.pl'

# same, shared access sets:

puts acl.output         # original access set
puts t.sock.acl.output  # socket's access set
puts t.acl.output       # Telnet's access set

t.acl_recheck

