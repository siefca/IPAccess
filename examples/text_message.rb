$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/socket'

IPAccess::Set::Global.output.blacklist '::0'

begin
  s = IPAccess::TCPSocket.new('::0', 80)
rescue IPAccessDenied => e
  puts "Message: #{e.message}"
  puts
  puts "Exception: #{e.inspect}"
  puts "Remote IP: #{e.peer_ip}"
  puts "Rule: #{e.rule}"
  puts "Originator: #{e.originator}"
  puts "Internal Originator in CIDR: #{e.peer_ip.tag[:Originator]}"
  puts "ACL: #{e.acl}"
end

puts "\n\n-------------------- next example\n\n"

begin
  IPAccess::Set::Global.check_out('randomseed.pl')
rescue IPAccessDenied => e
  puts "Message: #{e.message}"
  puts
  puts "Exception: #{e.inspect}"
  puts "Remote IP: #{e.peer_ip}"
  puts "Rule: #{e.rule}"
  puts "Originator: #{e.originator}"
  puts "Internal Originator in CIDR: #{e.peer_ip.tag[:Originator]}"
  puts "ACL: #{e.acl}"
end

puts "\n\n-------------------- next example\n\n"

begin
  acl = IPAccess::Set.new
  acl.input.blacklist :local, :private
  puts acl.show
  s = IPAccess::TCPServer.new(31337, acl)
  s.opened_on_deny = true
  puts "\nnow use terminal and issue: telnet 127.0.0.1 31337\n"
  n  = s.accept
rescue IPAccessDenied => e
  puts "Message: #{e.message}"
  puts
  puts "Exception: #{e.inspect}"
  puts "Remote IP: #{e.peer_ip} (#{e.peer_ip_short})"
  puts "Rule: #{e.rule} (#{e.rule_short})"
  puts "Originator: #{e.originator}"
  puts "Internal Originator in CIDR: #{e.peer_ip.tag[:Originator]}"
  puts "ACL: #{e.acl}"
  
  unless e.originator.closed?
    e.originator.write("Access denied!!!\n\r\n\r")
    e.originator.close
  end
end

