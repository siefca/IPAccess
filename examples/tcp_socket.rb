$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess'

IPAccess::Global.output.blacklist 'randomseed.pl'
IPAccess.arm TCPSocket
s = TCPSocket.new('randomseed.pl', 80)


