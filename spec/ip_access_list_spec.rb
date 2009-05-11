$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'uri'
require 'socket'
require 'ipaddr'
require 'ipaccess'

describe IPAccessList do

    before(:each) do
      @list = IPAccessList.new
    end

    describe "initializer" do
          
      it "should take an empty array as parameter" do
        lambda { IPAccessList.new [] }.should_not raise_error
      end
      
      it "should take array of strings describing IPs as parameter" do
        lambda { IPAccessList.new ["192.168.0.0/16", "127.0.0.1"] }.should_not raise_error
      end
      
      it "should take array of names as parameter" do
        lambda { IPAccessList.new ["localhost"] }.should_not raise_error
      end

      it "should take array of symbols as parameter" do
        lambda { IPAccessList.new [:local, :private] }.should_not raise_error
      end

      it "should take array of URLs as parameter" do
        lambda { IPAccessList.new ["http://localhost/","https://127.0.0.2/"] }.should_not raise_error
      end
      
      it "should take array of sockets as parameter" do
        s1 = UDPSocket.new
        s2 = UDPSocket.new
        def s1.peeraddr; [1,2,'127.0.0.1','127.0.0.1'] end
        def s2.peeraddr; [1,2,'127.0.0.2','127.0.0.2'] end
        lambda { IPAccessList.new [s1, s2] }.should_not raise_error
      end

      it "should take array of IPAddr objects as parameter" do
        lambda { IPAccessList.new [IPAddr.new("127.0.0.1"), IPAddr.new("192.168.1.1")] }.should_not raise_error
      end

      it "should take array of numbers as parameter" do
        lambda { IPAccessList.new [2130706433,2130706434] }.should_not raise_error
      end

      it "should take array of URI objects as parameter" do
        lambda { IPAccessList.new [URI('http://localhost/'),URI('http://127.0.0.2:80/')] }.should_not raise_error
      end

    end

    # describe "add"
      
end
