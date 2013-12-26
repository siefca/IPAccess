$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'net/http'
require 'ipaccess/net/http'
require 'open-uri'

# Add host's IP by to black list of global output access set
IPAccess::Set::Global.output.blacklist :unusual

# Arm sockets
IPAccess.arm Net::HTTP

# Set some defaults
Net::HTTP.ipaccess_defaults = {
  :check_only_real => true,
  :opened_on_deny  => true
}

# Show blacklisted IP addresses
puts IPAccess::Set::Global.output.show

# Open URI
open 'http://localhost/'
