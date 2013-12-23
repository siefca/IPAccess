$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/telnet'     # load Net::Telnet version and IPAccess.arm method

opts = {}
opts["Host"]  = 'randomseed.pl'
opts["Port"]  = '80'

t = Net::Telnet.new(opts)       # try to connect to a remote host

begin

  IPAccess.arm t                  # arm single Telnet object (will use global access set)
  t.blacklist! 'randomseed.pl'    # blacklist host while being connected

rescue IPAccessDenied => e

  puts "Message:\t#{e.message}"
  puts
  puts "ACL:\t\t#{e.acl}"
  puts "Exception:\t#{e.inspect}"
  puts "Remote IP:\t#{e.peer_ip}"
  puts "Rule:\t\t#{e.rule}"
  puts "Originator:\t#{e.originator}"
  puts "CIDR's Origin:\t#{e.peer_ip.tag[:Originator]}\n\n"
  puts "Session closed:\t#{t.closed?}"
  
end

p t
p "end"

