$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/pop'

# Add host's IP by to black list of global output access set
IPAccess::Set::Global.output.blacklist 'randomseed.pl'

# Create custom access set with one blacklisted IP
acl = IPAccess::Set.new
acl.output.blacklist 'randomseed.pl'
acl.output.blacklist 'gmail.com'

###### Example cases

# 1

i = 0
IPAccess::Net::POP3.delete_all('randomseed.pl', 110,
                     'YourAccount', 'YourPassword') do |m|
  File.open("inbox/#{i}", 'w') do |f|
    f.write m.pop
  end
  i += 1
end

# 2

p = Net::POP3.new 'randomseed.pl'
IPAccess.arm p, acl
p.auth_only 'user', 'pass'

