$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/http'
require 'uri'

url = URI.parse('http://randomseed.pl/index.html')

# Add host's IP by to black list of global output access set
IPAccess::Global.output.blacklist 'randomseed.pl'

# Create custom access set with one blacklisted IP
acl = IPAccess.new
acl.output.blacklist 'randomseed.pl'

###### Example cases

# Case 0: simple setup with custom ACL

res = IPAccess::Net::HTTP.start(url.host, url.port, acl) { |http|
  http.get("/#{url.path}")
}

# Case 1: custom access set with Net::HTTP variant

req = Net::HTTP::Get.new(url.path)
htt = IPAccess::Net::HTTP.new(url.host, url.port, acl)
res = htt.start { |http|
  http.request(req)
}

# Case 2: global access set with Net::HTTP variant

req = Net::HTTP::Get.new(url.path)
htt = IPAccess::Net::HTTP.new(url.host, url.port)
res = htt.start { |http|
  http.request(req)
}

# Case 3: global access set with Net::HTTP variant

req = Net::HTTP::Get.new(url.path)
res = IPAccess::Net::HTTP.start(url.host, url.port) { |http|
  http.request(req)
}

# Case 4: get_print with custom ACL

IPAccess::Net::HTTP.get_print 'randomseed.pl', '/index.html', acl

# Case 5: arming Net::HTTP class

# Arm Net::HTTP class of Ruby
IPAccess.arm Net::HTTP
# Call IPAccess::Net::HTTP.get_print
IPAccess::Net::HTTP.get_print 'randomseed.pl', '/index.html'
# Call Net::HTTP.get_print
Net::HTTP.get_print 'randomseed.pl', '/index.html'

