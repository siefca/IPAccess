$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

['ip_access_list_spec'].each do |spec|
  require File.join(File.dirname(__FILE__), spec)
end
