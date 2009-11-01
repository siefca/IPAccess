$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/socket'

begin
  
  # add some rules
  acl = IPAccess::Set.new
  acl.input.blacklist_reasonable "Local and private addresses aren't welcome here", :local, :private
  acl.input.whitelist_reasonable "I like that system, it makes toasts", '172.16.0.10', '1234:1234:1234:1234:1234:1234:1234:1234'

  # show the lists with reasons for entries
  puts acl.show(true)

  # create a server
  s = IPAccess::TCPServer.new(31337, acl)
  
  # let it stays opened on access denied event
  s.opened_on_deny = true

  # listen for a connection
  puts "\nnow use terminal and issue: telnet 127.0.0.1 31337\n\n"
  n  = s.accept

rescue IPAccessDenied => e

  # show some stuff carried along with an exception
  puts "Message: #{e.message}"
  puts
  puts "Exception: #{e.inspect}"
  puts "Remote IP: #{e.peer_ip} (#{e.peer_ip_short})"
  puts "Rule: #{e.rule} (#{e.rule_short})"
  puts "Reason: #{e.reason}"
  puts "Originator: #{e.originator}"
  puts "Internal Originator in CIDR: #{e.peer_ip.tag[:Originator]}"
  puts "ACL: #{e.acl}"
  
  # send a reason to our peer before closing connection
  unless e.originator.closed?
    e.originator.write(e.reason + "\n\r")
    e.originator.close
  end

end

