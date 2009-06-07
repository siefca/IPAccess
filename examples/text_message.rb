$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess'

IPAccess::Global.input.blacklist :local, :private

IPAccess.arm TCPSocket
s = TCPSocket.new('randomseed.pl', 80)

