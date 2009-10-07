$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess'

IPAccess::Set::Global.input.blacklist :local, :private

IPAccess.arm TCPSocket
s = TCPSocket.new('randomseed.pl', 80)

