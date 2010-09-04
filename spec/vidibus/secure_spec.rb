require "spec_helper"

describe "Vidibus::Secure" do
  let(:key) { "8KTbTanrBTQ5c8CjANpJQjPWcIstFxq/uFIUQBF3gRnztM565xIfe8MStVcLilbEhjYwfZiD4lFWINF22Aw8gVEbkSf2rLN0fnuO9YtNqFLQU6m/OldO5JbsBJPCwuzsPYmZ1w==" }
  let(:data) { "My name is Bond. You know the rest." }
  let(:encrypted_base64) { "hXUWa3gHRpYr/Fi2qm9xdTyZg7NSpYq8X2p1EL+/wffUg9IeIjVbSvyUYAvy\nTLbc\n" }
  let(:encrypted_hex) { "8575166b780746962bfc58b6aa6f71753c9983b352a58abc5f6a7510bfbfc1f7d483d21e22355b4afc94600bf24cb6dc" }
  let(:signature_base64) { "AhTlmymUI9q2bdrtJ0vLdyV8Y8eUf2U5xrzoK5PdWKQ=\n" }
  let(:signature_hex) { "0214e59b299423dab66ddaed274bcb77257c63c7947f6539c6bce82b93dd58a4" }
  let(:base64_format) { /([A-Z]|\+|\/)/ }
  let(:hex_format) { /^[0-9a-f]+$/ }
  
  describe ".settings" do
    context "for :random" do
      it "should default to a length of 50" do
        Vidibus::Secure.settings[:random][:length].should eql(50)
      end
      
      it "should default to base64 encoding" do
        Vidibus::Secure.settings[:random][:encoding].should eql(:base64)
      end
    end
    
    context "for :sign" do
      it "should default to SHA256 algorithm" do
        Vidibus::Secure.settings[:sign][:algorithm].should eql("SHA256")
      end
      
      it "should default to hex encoding" do
        Vidibus::Secure.settings[:sign][:encoding].should eql(:hex)
      end
    end
    
    context "for :crypt" do
      it "should default to AES-256-CBC algorithm" do
        Vidibus::Secure.settings[:crypt][:algorithm].should eql("AES-256-CBC")
      end
      
      it "should default to base64 encoding" do
        Vidibus::Secure.settings[:crypt][:encoding].should eql(:base64)
      end
    end
  end
  
  describe ".random" do
    it "should create a base64 random string with a length of 50 chars" do
      random = Vidibus::Secure.random
      random.length.should eql(50)
      random.should match(base64_format)
    end
    
    it "should create a hexadecimal random string with a length of 50 chars if :encoding is provided" do
      random = Vidibus::Secure.random(:encoding => :hex)
      random.length.should eql(50)
      random.should match(hex_format)
    end
    
    it "should create a random string with a length of 60 chars if :length is provided" do
      Vidibus::Secure.random(:length => 60).length.should eql(60)
    end
    
    it "should create a hexadecimal random string if settings for :random are changed" do
      Vidibus::Secure.settings[:random][:encoding] = :hex
      Vidibus::Secure.random.should match(hex_format)
      Vidibus::Secure.settings[:random][:encoding] = :base64
    end
  end
  
  describe ".sign" do
    it "should create a hexadecimal signature of given data by default" do
      Vidibus::Secure.sign(data, key).should eql(signature_hex)
    end
    
    it "should create a base64 signature of given data if :encoding is provided" do
      Vidibus::Secure.sign(data, key, :encoding => :base64).should eql(signature_base64)
    end
    
    it "should create a base64 signature of given data if settings for :sign are changed" do
      Vidibus::Secure.settings[:sign][:encoding] = :base64
      Vidibus::Secure.sign(data, key).should eql(signature_base64)
      Vidibus::Secure.settings[:sign][:encoding] = :hex
    end
  end
  
  describe ".encrypt" do
    it "should encrypt data as base64 string" do
      Vidibus::Secure.encrypt(data, key).should eql(encrypted_base64)
    end
    
    it "should encrypt data as hexadecimal string if :encoding is provided" do
      Vidibus::Secure.encrypt(data, key, :encoding => :hex).should eql(encrypted_hex)
    end
    
    it "should encrypt data as hexadecimal string if encoding settings for :crypt are set to hex" do
      Vidibus::Secure.settings[:crypt][:encoding] = :hex
      Vidibus::Secure.encrypt(data, key).should eql(encrypted_hex)
      Vidibus::Secure.settings[:crypt][:encoding] = :base64
    end
  end
  
  describe ".decrypt" do
    it "should decrypt a base64 string" do
      Vidibus::Secure.decrypt(encrypted_base64, key).should eql(data)
    end
    
    it "should decrypt a hexadecimal string if :encoding is provided" do
      Vidibus::Secure.decrypt(encrypted_hex, key, :encoding => :hex).should eql(data)
    end
    
    it "should decrypt a hexadecimal string if encoding settings for :crypt are set to hex" do
      Vidibus::Secure.settings[:crypt][:encoding] = :hex
      Vidibus::Secure.decrypt(encrypted_hex, key).should eql(data)
      Vidibus::Secure.settings[:crypt][:encoding] = :base64
    end
  end
  
  describe ".sign_request" do
    it "should not modifiy params for all requests except POST and PUT" do
      for verb in %w[get delete head options]
        path, params = Vidibus::Secure.sign_request(verb, "/", {:hey => :dude}, key)
        params.should eql({:hey => :dude})
      end
    end
    
    it "should not modifiy path for POST and PUT requests" do
      for verb in %w[post put]
        path, params = Vidibus::Secure.sign_request(verb, "/whazzup", {}, key)
        path.should eql("/whazzup")
      end
    end
    
    context "for GET request" do    
      it "should accept a custom name as signature param" do
        path, params = Vidibus::Secure.sign_request(:get, "http://vidibus.org/status", {}, key, "privado")
        path.should eql("http://vidibus.org/status?privado=09247a2534f14e57081193ef6834b08843352c796af264f77e76445472dae9ed")
      end
      
      it "should create a signature of a given URL" do
        path, params = Vidibus::Secure.sign_request(:get, "http://vidibus.org/", {}, key)
        path.should eql("http://vidibus.org/?sign=0ff9ec7056fd6a2b8ea1d2a1f462458719e3cf0b65485c55035ac906fd3d3368")
      end
      
      it "should create identical signatures for URLs with and without trailing slash" do
        signature = "0ff9ec7056fd6a2b8ea1d2a1f462458719e3cf0b65485c55035ac906fd3d3368"
        Vidibus::Secure.sign_request(:get, "http://vidibus.org", {}, key).first.should match(signature)
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/", {}, key).first.should match(signature)
      end
      
      it "should create a signature of a given URI" do
        path, params = Vidibus::Secure.sign_request(:get, "http://vidibus.org/status", {}, key)
        path.should eql("http://vidibus.org/status?sign=09247a2534f14e57081193ef6834b08843352c796af264f77e76445472dae9ed")
      end
      
      it "should create identical signatures for URIs with and without trailing slash" do
        signature = "09247a2534f14e57081193ef6834b08843352c796af264f77e76445472dae9ed"
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/status", {}, key).first.should match(signature)
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/status/", {}, key).first.should match(signature)
      end
      
      it "should create a signature of URI with params" do
        path, params = Vidibus::Secure.sign_request(:get, "http://vidibus.org/status?type=server", {}, key)
        path.should eql("http://vidibus.org/status?type=server&sign=068dbf2695798e3cda2710ae34d74043653eae41d82cbbdf39edebd7e2ae9a50")
      end
      
      it "should create identical signatures for URIs with params with and without trailing slash" do
        signature = "068dbf2695798e3cda2710ae34d74043653eae41d82cbbdf39edebd7e2ae9a50"
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/status?type=server", {}, key).first.should match(signature)
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/status/?type=server", {}, key).first.should match(signature)
      end
      
      it "should replace signature in URI with params" do
        path, params = Vidibus::Secure.sign_request(:get, "http://vidibus.org/status?interval=2&sign=something&type=server", {}, key)
        path.should eql("http://vidibus.org/status?interval=2&sign=4a82dca2318108158f13d2d79915877efe550ffd1cb2dbe9753c2872803ae23d&type=server")
      end
      
      it "should replace signature in URI without other params" do
        path, params = Vidibus::Secure.sign_request(:get, "http://vidibus.org/status?sign=something", {}, key)
        path.should eql("http://vidibus.org/status?sign=f4d3b1cf13614a5212fe46badb920747ed18c3c329fbd384efbdd70c26297b99")
      end
    end
    
    context "for POST request" do
      it "should create a signature of path and params" do
        path, params = Vidibus::Secure.sign_request(:post, "http://vidibus.org/create", {:some => "thing"}, key)
        params[:some].should eql("thing")
        params[:sign].should eql("90c71e477ea155e99b8a85b7f9ad0614e5445acfc33702cd3db614941f1a7df9")
      end
      
      it "should replace existing signature" do
        path, params = Vidibus::Secure.sign_request(:post, "http://vidibus.org/create", {:some => "thing", :sign => "something"}, key)
        params[:some].should eql("thing")
        params[:sign].should eql("90c71e477ea155e99b8a85b7f9ad0614e5445acfc33702cd3db614941f1a7df9")
      end
      
      it "should add signature param as string if params are given as strings" do
        path, params = Vidibus::Secure.sign_request(:post, "/", {"some" => "thing"}, key)
        params["some"].should eql("thing")
        params["sign"].should_not be_nil
      end
      
      it "should add signature param as symbol if params are given as symbols" do
        path, params = Vidibus::Secure.sign_request(:post, "/", {:some => "thing"}, key)
        params[:some].should eql("thing")
        params[:sign].should_not be_nil
      end
      
      it "should add signature param as symbol if no params are given" do
        path, params = Vidibus::Secure.sign_request(:post, "/", {}, key)
        params[:sign].should_not be_nil
      end
    end
  end
  
  describe ".verify_request" do
    it "should return true for a valid GET request" do
      path = "http://vidibus.org/status?type=server&sign=068dbf2695798e3cda2710ae34d74043653eae41d82cbbdf39edebd7e2ae9a50"
      Vidibus::Secure.verify_request(:get, path, {}, key).should be_true
    end
    
    it "should return true for a valid GET request even if verb is upcase" do
      path = "http://vidibus.org/status?type=server&sign=068dbf2695798e3cda2710ae34d74043653eae41d82cbbdf39edebd7e2ae9a50"
      Vidibus::Secure.verify_request("GET", path, {}, key).should be_true
    end
    
    it "should discard additional params for a GET request" do
      path = "http://vidibus.org/status?type=server&sign=068dbf2695798e3cda2710ae34d74043653eae41d82cbbdf39edebd7e2ae9a50"
      Vidibus::Secure.verify_request("GET", path, { :some => "thing" }, key).should be_true
    end
    
    it "should return true for a valid POST request with params given as symbols" do
      path = "http://vidibus.org/create"
      params = {:sign => "90c71e477ea155e99b8a85b7f9ad0614e5445acfc33702cd3db614941f1a7df9", :some => "thing"}
      Vidibus::Secure.verify_request(:post, path, params, key).should be_true
    end
    
    it "should return true for a valid POST request with params given as string" do
      path = "http://vidibus.org/create"
      params = {"sign"=>"90c71e477ea155e99b8a85b7f9ad0614e5445acfc33702cd3db614941f1a7df9", "some"=>"thing"}
      Vidibus::Secure.verify_request(:post, path, params, key).should be_true
    end
    
    it "should return false if signature is invalid" do
      path = "http://vidibus.org/status?type=server&sign=invalid"
      Vidibus::Secure.verify_request(:get, path, {}, key).should be_false
    end
    
    it "should return false if path does not match signature" do
      path = "http://vidibus.org/invalid?type=server&sign=068dbf2695798e3cda2710ae34d74043653eae41d82cbbdf39edebd7e2ae9a50"
      Vidibus::Secure.verify_request(:get, path, {}, key).should be_false
    end
    
    it "should return false if request verb does not match signature" do
      path = "http://vidibus.org/status?type=server&sign=068dbf2695798e3cda2710ae34d74043653eae41d82cbbdf39edebd7e2ae9a50"
      Vidibus::Secure.verify_request(:delete, path, {}, key).should be_false
    end
    
    it "should return false if params do not match signature" do
      path = "http://vidibus.org/create"
      params = {"sign" => "90c71e477ea155e99b8a85b7f9ad0614e5445acfc33702cd3db614941f1a7df9", "some" => "invalid"}
      Vidibus::Secure.verify_request(:post, path, params, key).should be_false
    end
    
    it "should return false if signature does not match params" do
      path = "http://vidibus.org/create"
      params = {"sign" => "invalid", "some" => "thing"}
      Vidibus::Secure.verify_request(:post, path, params, key).should be_false
    end
  end
end
