$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/http'

IPAccess::Global.output.blacklist 'randomseed.pl'
IPAccess.arm Net::HTTP

#IPAccess::Net::HTTP.get_print 'randomseed.pl', '/index.html'
Net::HTTP.get_print 'randomseed.pl', '/index.html'
