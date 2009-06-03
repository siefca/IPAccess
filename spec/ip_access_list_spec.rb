$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'uri'
require 'socket'
require 'rubygems'
require 'ipaccess'

describe IPAccessList do
 
    describe "initializer" do
           
      it "should take an empty array as parameter" do
        lambda { IPAccessList.new [] }.should_not raise_error
      end
      
      it "should take an array of strings describing IPs as parameter" do
        lambda { IPAccessList.new ["192.168.0.0/16", "127.0.0.1"] }.should_not raise_error
      end
      
      it "should take an array of names as parameter" do
        lambda { IPAccessList.new ["localhost"] }.should_not raise_error
      end

      it "should take an array of symbols as parameter" do
        lambda { IPAccessList.new [:local, :private] }.should_not raise_error
      end

      it "should take an array of URLs as parameter" do
        lambda { IPAccessList.new ["http://localhost/","https://127.0.0.2/"] }.should_not raise_error
      end
      
      it "should take an array of sockets as parameter" do
        s1 = UDPSocket.new
        s2 = UDPSocket.new
        def s1.peeraddr; [1,2,'127.0.0.1','127.0.0.1'] end
        def s2.peeraddr; [1,2,'127.0.0.2','127.0.0.2'] end
        lambda { IPAccessList.new [s1, s2] }.should_not raise_error
      end

      it "should take an array of IPAddr objects as parameter" do
        lambda { IPAccessList.new [IPAddr.new("127.0.0.1"), IPAddr.new("192.168.1.1")] }.should_not raise_error
      end

      it "should take an array of numbers as parameter" do
        lambda { IPAccessList.new [2130706433,2130706434] }.should_not raise_error
      end

      it "should take an array of URI objects as parameter" do
        lambda { IPAccessList.new [URI('http://localhost/'),URI('http://127.0.0.2:80/')] }.should_not raise_error
      end

      it "should take an array of CIDR objects as parameter" do
        lambda { IPAccessList.new [NetAddr::CIDR.create('192.168.1.1'),NetAddr::CIDR.create('192.168.0.0/24')] }.should_not raise_error
      end
      
      it "should take an array of NetAddr::Tree objects as parameter" do
        tree = NetAddr::Tree.new
        tree.add!('192.168.0.0/24')
        tree.add!('172.16.0.0')
        lambda { IPAccessList.new [tree] }.should_not raise_error
      end
      
      it "should take an array of IPAccessList objects as parameter" do
        tree = IPAccessList.new
        tree.add!('192.168.0.0/24')
        tree.add!('172.16.0.0')
        lambda { z = IPAccessList.new [tree] }.should_not raise_error
      end
     
    end # inicializer
      
    describe "access" do
    
      before(:each) do
        @access = IPAccessList.new
      end
          
      it "should deny access when single IP is blacklisted" do
        @access.blacklist '192.168.0.1'
        @access.denied('192.168.0.1').first.should == '192.168.0.1/32'
      end
      
      it "should deny access when single IP is blacklisted and neighbour is whitelisted" do
        @access.whitelist '192.168.0.1', '192.168.0.3'
        @access.blacklist '192.168.0.2'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
        
        @access.whitelist '172.16.0.1', '172.16.0.3'
        @access.blacklist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
      end

      it "should deny access when single IP is blacklisted and neighbour is blacklisted" do
        @access.blacklist '192.168.0.1', '192.168.0.2', '192.168.0.3'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'

        @access.whitelist '172.16.0.1', '172.16.0.3'
        @access.blacklist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
      end

      it "should deny access when single IP is blacklisted and parent is blacklisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.2'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
        
        @access.whitelist '172.16.0.1', '172.16.0.3'
        @access.blacklist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
      end
      
      it "should deny access when single IP is blacklisted, parent is blacklisted and neighbours are blacklisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.1', '192.168.0.2', '192.168.0.3'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
        
        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.blacklist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
      end
      
      it "should deny access when single IP is blacklisted, parent is blacklisted and neighbours are whitelisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.2'
        @access.whitelist '192.168.0.1', '192.168.0.3'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
        
        @access.whitelist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
      end
      
      it "should deny access when single IP is blacklisted, parent is blacklisted and parent's neigbour is blacklisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.1', '192.168.0.2', '192.168.0.3'
        @access.blacklist '192.168.1.0/24'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
        
        @access.blacklist '172.16.0.2', '127.0.0.1', '172.16.0.1', '172.16.0.3'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'
      end
      
      it "should deny access when single IP is blacklisted, parent is blacklisted and parent's neigbour is whitelisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.1', '192.168.0.2', '192.168.0.3'
        @access.whitelist '192.168.1.0/24'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'

        @access.blacklist '172.16.0.1', '172.16.0.3'
        @access.whitelist '172.16.0.2', '127.0.0.1'
        @access.denied('192.168.0.2').first.should == '192.168.0.2/32'      
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
        @access.denied('192.168.0.1').first.should == '192.168.0.0/24'
      end

      it "should deny access when IP class is blacklisted and parent is blacklisted" do
        @access.blacklist '192.168.0.0/24', '192.168.0.0/16'
        @access.denied('192.168.0.1').first.should == '192.168.0.0/24'
      end
      
      it "should deny access when IP class is blacklisted and neighbour classes are blacklisted" do
        @access.blacklist '192.168.0.0/24', '172.16.0.0/24', '10.0.0.0/12'
        @access.denied('192.168.0.1').first.should == '192.168.0.0/24'
      end

      it "should deny access when IP class is blacklisted and neighbour classes are whitelisted" do
        @access.blacklist '192.168.0.0/24'
        @access.whitelist '172.16.0.0/24', '10.0.0.0/12', '255.255.0.0/24'
        @access.denied('192.168.0.1').first.should == '192.168.0.0/24'
      end
      
      it "should deny access when IP class is blacklisted and contains whitelisted items" do
        @access.blacklist '192.168.0.0/24', '127.0.0.1', '10.0.0.1/12'
        @access.whitelist '192.168.0.1', '192.168.0.3'
        @access.denied('192.168.0.2').first.should == '192.168.0.0/24'
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
