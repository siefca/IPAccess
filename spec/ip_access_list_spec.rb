$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'uri'
require 'socket'
require 'rubygems'
require 'ipaddr'
require 'ipaccess'
require 'ipaccess/socket'

begin
  require 'ipaddr_list'
rescue LoadError
end

describe IPAccess::List::Check do
 
    describe "initializer" do
           
      it "should take an empty array as parameter" do
        lambda { IPAccess::List::Check.new [] }.should_not raise_error
      end
      
      it "should take an array of strings describing IPs as parameter" do
        lambda { IPAccess::List::Check.new ["192.168.0.0/16", "127.0.0.1"] }.should_not raise_error
      end
      
      it "should take an array of names as parameter" do
        lambda { IPAccess::List::Check.new ["localhost"] }.should_not raise_error
      end

      it "should take an array of symbols as parameter" do
        lambda { IPAccess::List::Check.new [:local, :private] }.should_not raise_error
      end

      it "should take an array of URLs as parameter" do
        lambda { IPAccess::List::Check.new ["http://localhost/","https://127.0.0.2/"] }.should_not raise_error
      end
      
      it "should take an array of sockets as parameter" do
        s1 = UDPSocket.new
        s2 = UDPSocket.new
        def s1.getpeername; "\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" end
        def s2.getpeername; "\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" end
        lambda { IPAccess::List::Check.new [s1, s2] }.should_not raise_error
      end

      it "should take an array of IPAddr objects as parameter" do
        lambda { IPAccess::List::Check.new [IPAddr.new("127.0.0.1"), IPAddr.new("192.168.1.1")] }.should_not raise_error
      end

      if Kernel.const_defined?(:IPAddrList)
        it "should take an IPAddrList object as parameter" do
          lambda { IPAccess::List::Check.new IPAddrList.new(["127.0.0.1", "192.168.1.1"]) }.should_not raise_error
        end
      end

      it "should take an array of numbers as parameter" do
        lambda { IPAccess::List::Check.new [2130706433,2130706434] }.should_not raise_error
      end

      it "should take an array of URI objects as parameter" do
        lambda { IPAccess::List::Check.new [URI('http://localhost/'),URI('http://127.0.0.2:80/')] }.should_not raise_error
      end

      it "should take an array of URI strings as parameter" do
        lambda { IPAccess::List::Check.new ['http://localhost/','http://127.0.0.2:80'] }.should_not raise_error
      end

      it "should take an array of CIDR objects as parameter" do
        lambda { IPAccess::List::Check.new [NetAddr::CIDR.create('192.168.1.1'),NetAddr::CIDR.create('192.168.0.0/24')] }.should_not raise_error
      end
      
      it "should take an array of NetAddr::Tree objects as parameter" do
        tree = NetAddr::Tree.new
        tree.add!('192.168.0.0/24')
        tree.add!('172.16.0.0')
        lambda { IPAccess::List::Check.new [tree] }.should_not raise_error
      end
      
      it "should take an array of IPAccess::List::Check objects as parameter" do
        tree = IPAccess::List::Check.new
        tree.add!('192.168.0.0/24')
        tree.add!('172.16.0.0')
        lambda { z = IPAccess::List::Check.new [tree] }.should_not raise_error
      end

      it "should take an array of hostnames as parameter" do
        lambda { IPAccess::List::Check.new ['localhost'] }.should_not raise_error
      end
      
      it "should take an array of hostnames with masks as parameter" do
        lambda { IPAccess::List::Check.new ['localhost/24','localhost/255.255.0.0'] }.should_not raise_error
      end
      
    end

    describe "rules" do
    
      before(:each) do
        @access = IPAccess::List::Check.new
        @access.blacklist :local, '192.168.0.1', :private
        @access.whitelist '172.16.10.0/24', '192.168.0.2'
      end

      it "should be searchable by matching IP to rules" do
        @access.included('192.168.0.1').first.should == '192.168.0.1/32'
        @access.included('192.168.0.2').first.should == '192.168.0.2/32'
        @access.included('192.168.2.5').first.should == '192.168.0.0/16'
        @access.included('1.2.3.5').first.should == nil
        @access.included('127.0.0.5/16').first.should == '127.0.0.0/8'
      end
        
    end # rules
    
    describe "access" do
    
      before(:each) do
        @access = IPAccess::List::Check.new
      end
          
      it "should deny access when single IP is blacklisted" do
        @access.blacklist '192.168.0.1'
        @access.denied('192.168.0.1').first[:IP].should == '192.168.0.1/32'
      end
      
      it "should deny access when single IP is blacklisted and neighbour is whitelisted" do
        @access.whitelist '192.168.0.1', '192.168.0.3'
        @access.blacklist '192.168.0.2'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'
        
        @access.whitelist '172.16.0.1', '172.16.0.3'
        @access.blacklist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first[:Rule].should == '192.168.0.2/32'
      end

      it "should deny access when single IP is blacklisted and neighbour is blacklisted" do
        @access.blacklist '192.168.0.1', '192.168.0.2', '192.168.0.3'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'

        @access.whitelist '172.16.0.1', '172.16.0.3'
        @access.blacklist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'
      end

      it "should deny access when single IP is blacklisted and parent is blacklisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.2'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'
        
        @access.whitelist '172.16.0.1', '172.16.0.3'
        @access.blacklist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'
      end
      
      it "should deny access when single IP is blacklisted, parent is blacklisted and neighbours are blacklisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.1', '192.168.0.2', '192.168.0.3'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'
        
        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.blacklist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'
      end
      
      it "should deny access when single IP is blacklisted, parent is blacklisted and neighbours are whitelisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.2'
        @access.whitelist '192.168.0.1', '192.168.0.3'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'
        
        @access.whitelist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'
      end
      
      it "should deny access when single IP is blacklisted, parent is blacklisted and parent's neigbour is blacklisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.1', '192.168.0.2', '192.168.0.3'
        @access.blacklist '192.168.1.0/24'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'
        
        @access.blacklist '172.16.0.2', '127.0.0.1', '172.16.0.1', '172.16.0.3'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'
      end
      
      it "should deny access when single IP is blacklisted, parent is blacklisted and parent's neigbour is whitelisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.1', '192.168.0.2', '192.168.0.3'
        @access.whitelist '192.168.1.0/24'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'

        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first[:IP].should == '192.168.0.2/32'      
      end

      it "should not deny access when single IP is not present" do
        @access.blacklist '192.168.0.0/24', '192.168.0.1', '192.168.0.2', '192.168.0.3'
        @access.whitelist '192.168.1.0/24'
        @access.denied('127.0.0.1').first.should == nil
        
        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('1.1.0.1').first.should == nil        
      end
      
      it "should not deny access when single IP is whitelisted" do
        @access.whitelist '192.168.1.0/24'
        @access.denied('192.168.0.1').first.should == nil
        
        @access.blacklist '192.168.1.2', '192.168.1.3'
        @access.denied('192.168.0.1').first.should == nil
        
        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.1').first.should == nil
      end
      
      it "should not deny access when single IP is whitelisted and parent is blacklisted" do
        @access.blacklist '192.168.1.0/24'
        @access.whitelist '192.168.1.2'
        @access.denied('192.168.0.1').first.should == nil
        
        @access.blacklist '192.168.1.1', '192.168.1.3'
        @access.denied('192.168.0.2').first.should == nil
        
        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1', '192.168.1.1', '192.168.1.3'
        @access.denied('192.168.0.2').first.should == nil
      end
            
      it "should not deny access when single IP is blacklisted and whitelisted" do
        @access.blacklist '192.168.0.1'
        @access.whitelist '192.168.0.1'
        @access.denied('192.168.0.1').first.should == nil

        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.1').first.should == nil
      end

      it "should not deny access when single IP is blacklisted and parent is whitelisted" do
        @access.whitelist '192.168.0.0/24'
        @access.blacklist '192.168.0.1'
        @access.denied('192.168.0.1').first.should == nil
        
        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.1').first.should == nil
      end
      
      it "should not deny access when single IP is blacklisted, parent is whitelisted and neighbour is blacklisted" do
        @access.whitelist '192.168.0.0/24'
        @access.blacklist '192.168.0.1'
        @access.blacklist '192.168.0.2'
        @access.blacklist '192.168.0.3'
        @access.denied('192.168.0.2').first.should == nil
        
        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.1').first.should == nil
      end
      
      it "should not deny access when single IP is blacklisted, parent is whitelisted and neighbours are whitelisted" do
        @access.whitelist '192.168.0.0/24'
        @access.whitelist '192.168.0.1'
        @access.blacklist '192.168.0.2'
        @access.whitelist '192.168.0.3'
        @access.denied('192.168.0.2').first.should == nil
        
        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.1').first.should == nil
      end
      
      it "should not deny access when single IP is blacklisted, but all is whitelisted" do
        @access.whitelist :all
        @access.blacklist '192.168.0.2'
        @access.denied('192.168.0.2').first.should == nil
        
        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.1').first.should == nil
      end
      
      it "should deny access when IP class is blacklisted" do
        @access.blacklist '192.168.0.0/24'
        @access.denied('192.168.0.1').first[:Rule].should == '192.168.0.0/24'
      end

      it "should deny access when IP class is blacklisted and parent is blacklisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.0/16'
        @access.denied('192.168.0.1').first[:Rule].should == '192.168.0.0/24'
      end
      
      it "should deny access when IP class is blacklisted and neighbour classes are blacklisted" do
        @access.blacklist '192.168.0.0/24', '172.16.0.0/24', '10.0.0.0/12'
        @access.denied('192.168.0.1').first[:Rule].should == '192.168.0.0/24'
      end

      it "should deny access when IP class is blacklisted and neighbour classes are whitelisted" do
        @access.blacklist '192.168.0.0/24'
        @access.whitelist '172.16.0.0/24', '10.0.0.0/12', '255.255.0.0/24'
        @access.denied('192.168.0.1').first[:Rule].should == '192.168.0.0/24'
      end
      
      it "should deny access when IP class is blacklisted and contains whitelisted items" do
        @access.blacklist '192.168.0.0/24', '127.0.0.1', '10.0.0.1/12'
        @access.whitelist '192.168.0.1', '192.168.0.3'
        @access.denied('192.168.0.2').first[:Rule].should == '192.168.0.0/24'
      end

      it "should not deny access when IP class is whitelisted and parent is whitelisted" do
        @access.whitelist '192.168.0.0/24', '192.168.0.0/16'
        @access.denied('192.168.0.1').first.should == nil
      end

      it "should not deny access when IP class is blacklisted and parent is whitelisted" do
        @access.blacklist '192.168.0.0/24'
        @access.whitelist '192.168.0.0/16'
        @access.denied('192.168.0.1').first.should == nil
      end
      
      it "should deny access when IP class is whitelisted and contains blacklisted items" do
        @access.whitelist '192.168.0.0/24', '127.0.0.1', '10.0.0.1/12'
        @access.blacklist '192.168.0.1', '192.168.0.3'
        @access.denied('192.168.0.2').first.should == nil
      end
      
    end # access

end
