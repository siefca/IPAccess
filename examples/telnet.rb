$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/telnet'     # load Net::Telnet version and IPAccess.arm method

opts = {}
opts["Host"]  = 'randomseed.pl'
opts["Port"]  = '80'

t = Net::Telnet.new(opts)       # try to connect to remote host
IPAccess.arm t                  # arm single Telnet object (will use global access set)
t.blacklist! 'randomseed.pl'    # blacklist host while being connected

