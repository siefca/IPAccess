$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/ftp'

# Add host's IP by to black list of global output access set
IPAccess::Global.output.blacklist 'randomseed.pl'

# Create custom access set with one blacklisted IP
acl = IPAccess.new
acl.output.blacklist 'randomseed.pl'

###### Example cases

# Using IPAccess::Net::FTP variant instead of Net::FTP

acl = IPAccess.new
ftp = IPAccess::Net::FTP.new('ftp.pld-linux.org')
ftp.passive = true
ftp.login
files = ftp.chdir('/')
ftp.blacklist 'ftp.pld-linux.org', :private
files = ftp.list('n*') # this command opens socket so there is no need to call acl_recheck
ftp.close

# Using patched Net::FTP object

acl = IPAccess.new
acl.output.blacklist 'ftp.pld-linux.org'
ftp = Net::FTP.new('ftp.pld-linux.org')
ftp.passive = true
ftp.login
IPAccess.arm ftp, acl
files = ftp.chdir('/')
files = ftp.list('n*')
ftp.close

# Using patched Net::FTP class

acl = IPAccess.new
IPAccess.arm Net::FTP
ftp = Net::FTP.new('ftp.pld-linux.org')
ftp.acl = acl
ftp.passive = true
ftp.login
files = ftp.chdir('/')
acl.output.blacklist 'ftp.pld-linux.org'
files = ftp.list('n*')
ftp.close
