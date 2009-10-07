$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'ipaccess/net/imap'

# Add host's IP by to black list of global output access set
IPAccess::Set::Global.output.blacklist 'randomseed.pl'

# Create custom access set with one blacklisted IP
acl = IPAccess::Set.new
acl.output.blacklist 'randomseed.pl'
acl.output.blacklist 'imap.heise.de'

###### Example cases

# 1

imap = IPAccess::Net::IMAP.new('randomseed.pl')
  imap.authenticate('LOGIN', 'joe_user', 'joes_password')
  imap.examine('INBOX')
  imap.search(["RECENT"]).each do |message_id|
    envelope = imap.fetch(message_id, "ENVELOPE")[0].attr["ENVELOPE"]
    puts "#{envelope.from[0].name}: \t#{envelope.subject}"
  end

# 2

imap = Net::IMAP.new('imap.heise.de', 'imaps', true, nil, false)

IPAccess.arm imap, acl
  
  imap.authenticate('LOGIN', 'joe_user', 'joes_password')
  imap.examine('INBOX')
  imap.search(["RECENT"]).each do |message_id|
    envelope = imap.fetch(message_id, "ENVELOPE")[0].attr["ENVELOPE"]
    puts "#{envelope.from[0].name}: \t#{envelope.subject}"
  end

