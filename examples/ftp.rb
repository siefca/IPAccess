$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/ftp'

# Add host's IP by to black list of global output access set
IPAccess::Set::Global.output.blacklist 'randomseed.pl'

# Create custom access set with one blacklisted IP
acl = IPAccess::Set.new
acl.output.blacklist 'randomseed.pl'

###### Example cases

begin
  IPAccess::Net::FTP.open('ftp.icm.edu.pl', acl) { |ftp|
    ftp.passive = true
    ftp.blacklist! 'ftp.icm.edu.pl'
    files = ftp.list('li*')
    puts files
  }

rescue IPAccessDenied => e

  puts e.show
  puts "Connection is " + (e.originator.closed? ? "closed" : "opened")
  
end

# Using IPAccess::Net::FTP variant instead of Net::FTP

ftp = IPAccess::Net::FTP.new('ftp.pld-linux.org', :private) # private access set
ftp.passive = true
ftp.login
files = ftp.chdir('/')
ftp.blacklist 'ftp.pld-linux.org'                           # blacklisting
files = ftp.list('n*') # this command opens socket so there is no need to call acl_recheck
ftp.close

# Using patched Net::FTP object

acl = IPAccess::Set.new
acl.output.blacklist 'ftp.pld-linux.org'
ftp = Net::FTP.new('ftp.pld-linux.org')
ftp.passive = true
ftp.login
IPAccess.arm ftp, acl
files = ftp.chdir('/')
files = ftp.list('n*')
ftp.close

# Using patched Net::FTP class

acl = IPAccess::Set.new
IPAccess.arm Net::FTP
ftp = Net::FTP.new('ftp.pld-linux.org')
ftp.acl = acl
ftp.passive = true
ftp.login
files = ftp.chdir('/')
acl.output.blacklist 'ftp.pld-linux.org'
files = ftp.list('n*')
ftp.close
