$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/http'

# Add host's IP by to black list of global output access set
IPAccess::Global.output.blacklist 'randomseed.pl'

# Variant 0: private access set with Net::HTTP variant

url = URI.parse('http://randomseed.pl/index.html')
req = Net::HTTP::Get.new(url.path)
htt = IPAccess::Net::HTTP.new(url.host, url.port, :private)
htt.acl.output.blacklist 'randomseed.pl'
res = htt.start { |http|
  http.request(req)
}

# Variant 0b: global access set with Net::HTTP variant

url = URI.parse('http://randomseed.pl/index.html')
req = Net::HTTP::Get.new(url.path)
htt = IPAccess::Net::HTTP.new(url.host, url.port)
res = htt.start { |http|
  http.request(req)
}

# Variant 1: global access set with Net::HTTP variant

url = URI.parse('http://randomseed.pl/index.html')
req = Net::HTTP::Get.new(url.path)
res = IPAccess::Net::HTTP.start(url.host, url.port) { |http|
  http.request(req)
}

# Variant 2: 

# Call IPAccess::Net::HTTP.get_print with private list
IPAccess::Net::HTTP.get_print 'randomseed.pl', '/index.html'

# Variant 3:

# Arm Net::HTTP class of Ruby
IPAccess.arm Net::HTTP

# Call IPAccess::Net::HTTP.get_print
#IPAccess::Net::HTTP.get_print 'randomseed.pl', '/index.html'

# Call Net::HTTP.get_print
#Net::HTTP.get_print 'randomseed.pl', '/index.html'
