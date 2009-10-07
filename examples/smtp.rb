$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/smtp'

# Add host's IP by to black list of global output access set
IPAccess::Set::Global.output.blacklist 'randomseed.pl'

# Create custom access set with one blacklisted IP
acl = IPAccess::Set.new
acl.output.blacklist 'randomseed.pl'
acl.output.blacklist 'gmail.com'

###### Example cases

# 1

IPAccess::Net::SMTP.start('randomseed.pl', 25) do |smtp|
  ;
end

# 2

p = Net::SMTP.new 'randomseed.pl'
IPAccess.arm p, acl
p.start 'user', 'pass'

