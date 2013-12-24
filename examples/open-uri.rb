$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/http'
require 'open-uri'

# Add host's IP by to black list of global output access set
IPAccess::Set::Global.output.blacklist 'example.org'

# Arm sockets
IPAccess.arm Net::HTTP

# Open URI
open 'http://example.org/'
