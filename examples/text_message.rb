$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/socket'

# work on to_cidrs and ensure that NetAddr::CIDR is never
# used as originator

s = TCPSocket.new('randomseed.pl', 80)
cidr  = IPAccess.to_cidrs(s).first
cidr  = IPAccess.to_cidrs(cidr, :include_origins).first
cidr = cidr.first
puts "cidr's originator tag is: #{cidr.tag[:Originator]}\n\n"

secik = IPAccess::Set.new
secik.input.blacklist 'randomseed.pl/16'

begin
  secik.check_in_cidr(cidr)
  #secik.check_in_socket(s)
rescue Exception => e
  puts "CIDR is #{cidr}"
  puts "originator is: #{e.originator}"
  puts "cidr's originator tag is: #{cidr.tag[:Originator]}"
end

exit 0

IPAccess::Set::Global.output.blacklist 'randomseed.pl/16'

begin
  s = IPAccess::TCPSocket.new('randomseed.pl', 80, :opened_on_deny)
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
  IPAccess::Set::Global.check_out(nil, 'randomseed.pl')
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
  s = IPAccess::TCPServer.new(31337, acl)
  s.opened_on_deny = true
  puts "\nnow use terminal and issue: telnet 127.0.0.1 31337\n"
  n  = s.accept
rescue IPAccessDenied => e
  puts "Message: #{e.message}"
  puts
  puts "Exception: #{e.inspect}"
  puts "Remote IP: #{e.peer_ip}"
  puts "Rule: #{e.rule}"
  puts "Originator: #{e.originator}"
  puts "Internal Originator in CIDR: #{e.peer_ip.tag[:Originator]}"
  puts "ACL: #{e.acl}"
  
  unless e.originator.closed?
    e.originator.write("Access denied!!!\n\r\n\r")
    e.originator.close
  end
end

