$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/telnet'                     # load Net::Telnet version and IPAccess.arm method

opts = {}
opts["Host"]  = 'randomseed.pl'
opts["Port"]  = '80'

t = Net::Telnet.new(opts)                         # try to connect to remote host

acl = IPAccess.new                                # create custom access set
acl.output.blacklist 'randomseed.pl'              # blacklist host
IPAccess.arm t, acl                               # arm single Telnet object


puts acl.output         # original access set
puts t.sock.acl.output  # socket's access set
puts t.acl.output       # Telnet's access set

t.acl_recheck

