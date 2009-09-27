$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/telnet'

# Add host's IP by to black list of global output access set
IPAccess::Global.output.blacklist 'localhost'

# Arm Net::Telnet class of Ruby
IPAccess.arm Net::Telnet

opts = {}
opts["Host"] = 'randomseed.pl'
opts["Port"] = '80'

# Try to connect to remote host
t = Net::Telnet.new(opts)

# add new rule and check again
IPAccess::Global.output.blacklist 'randomseed.pl'
t.acl_recheck
