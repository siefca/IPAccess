$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/socket'

IPAccess::Set::Global.output.blacklist 'randomseed.pl'

begin
  s = IPAccess::TCPSocket.new('randomseed.pl', 80, :opened_on_deny)
rescue IPAccessDenied => e
  puts "Message: #{e.message}"
  puts
  puts "Exception: #{e.inspect}"
  puts "Remote IP: #{e.peer_ip}"
  puts "Rule: #{e.rule}"
  puts "Originator: #{e.originator}"
  puts "ACL: #{e.acl}"
end

puts "\n\n-------------------- next example\n\n"

begin
  acl = IPAccess::Set.new
  acl.input.blacklist :local, :private
  s = IPAccess::TCPServer.new(31337, acl)
  s.close_on_deny = false
  puts "\nnow use terminal and issue: telnet 127.0.0.1 31337\n"
  n  = s.accept
rescue IPAccessDenied => e
  puts "Message: #{e.message}"
  puts
  puts "Exception: #{e.inspect}"
  puts "Remote IP: #{e.peer_ip}"
  puts "Rule: #{e.rule}"
  puts "Originator: #{e.originator}"
  puts "ACL: #{e.acl}"
  
  unless e.originator.closed?
    e.originator.write("Access denied!!!\n\r\n\r")
    e.originator.close
  end
end

