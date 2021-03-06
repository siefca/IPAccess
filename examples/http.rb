$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/http'
require 'uri'

url = URI.parse('http://randomseed.pl/index.html')

# Add host's IP by to black list of global output access set
IPAccess::Set::Global.output.blacklist 'randomseed.pl'

# Create custom access set with one blacklisted IP
acl = IPAccess::Set.new
acl.output.blacklist 'randomseed.pl'

#===== Example cases

# Case 0: custom access set and patched single instance

req = Net::HTTP::Get.new("/")

begin

  htt = Net::HTTP.new(url.host, url.port)
  IPAccess.arm htt

  res = htt.start { |http|
    http.request(req)
  }

rescue IPAccessDenied => e

  puts "Message:\t#{e.message}"
  puts
  puts "ACL:\t\t#{e.acl}"
  puts "Exception:\t#{e.inspect}"
  puts "Remote IP:\t#{e.peer_ip}"
  puts "Rule:\t\t#{e.rule}"
  puts "Originator:\t#{e.originator}"
  puts "CIDR's Origin:\t#{e.peer_ip.tag[:Originator]}\n\n"
  
end

# Case 1: simple setup with custom ACL
res = IPAccess::Net::HTTP.start(url.host, url.port, acl) { |http|
  http.get("/#{url.path}")
}

# Case 2: custom access set with Net::HTTP variant

req = Net::HTTP::Get.new(url.path)
htt = IPAccess::Net::HTTP.new(url.host, url.port, acl)
res = htt.start { |http|
  http.request(req)
}

# Case 3: global access set with Net::HTTP variant

req = Net::HTTP::Get.new(url.path)
htt = IPAccess::Net::HTTP.new(url.host, url.port)
res = htt.start { |http|
  http.request(req)
}

# Case 4: global access set with Net::HTTP variant

req = Net::HTTP::Get.new(url.path)
res = IPAccess::Net::HTTP.start(url.host, url.port) { |http|
  http.request(req)
}

# Case 5: get_print with custom ACL

IPAccess::Net::HTTP.get_print 'randomseed.pl', '/index.html', acl

# Case 6: arming Net::HTTP class

# Arm Net::HTTP class of Ruby
IPAccess.arm Net::HTTP
# Call Net::HTTP.get_print
Net::HTTP.get_print 'randomseed.pl', '/index.html'

