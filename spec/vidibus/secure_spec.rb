require "spec_helper"

describe "Vidibus::Secure" do
  let(:key) { "8KTbTanrBTQ5c8CjANpJQjPWcIstFxq/uFIUQBF3gRnztM565xIfe8MStVcLilbEhjYwfZiD4lFWINF22Aw8gVEbkSf2rLN0fnuO9YtNqFLQU6m/OldO5JbsBJPCwuzsPYmZ1w==" }
  let(:data) { "My name is Bond. You know the rest." }
  let(:data_hash) {{"name" => "James Bond"}}
  let(:data_array) {["Bond", "James"]}
  let(:encrypted_base64) { "hXUWa3gHRpYr/Fi2qm9xdTyZg7NSpYq8X2p1EL+/wffUg9IeIjVbSvyUYAvy\nTLbc\n" }
  let(:encrypted_base64_array) { "pG9SNq9r2fQVxCiN8jYNciukklnZ+5YagtCE0LAj2bg=\n" }
  let(:encrypted_base64_hash) { "kjV3/v52KcsGKoNs7zgcmHih90uvc+hP5X90s6X27GE=\n" }
  let(:encrypted_hex) { "8575166b780746962bfc58b6aa6f71753c9983b352a58abc5f6a7510bfbfc1f7d483d21e22355b4afc94600bf24cb6dc" }
  let(:encrypted_hex_array) { "8575166b780746962bfc58b6aa6f71753c9983b352a58abc5f6a7510bfbfc1f7d483d21e22355b4afc94600bf24cb6dc" }
  let(:encrypted_hex_hash) { "8575166b780746962bfc58b6aa6f71753c9983b352a58abc5f6a7510bfbfc1f7d483d21e22355b4afc94600bf24cb6dc" }
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

    it "should raise a KeyError if given secret key is nil" do
      expect {Vidibus::Secure.sign(data, nil)}.to raise_error(Vidibus::Secure::KeyError)
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

    it "should raise an error if given secret key is nil" do
      expect {Vidibus::Secure.sign(data, nil)}.to raise_error(Vidibus::Secure::KeyError)
    end

    it "should encrypt array data" do
      Vidibus::Secure.encrypt(data_array, key).should eql(encrypted_base64_array)
    end

    it "should encrypt hash data" do
      Vidibus::Secure.encrypt(data_hash, key).should eql(encrypted_base64_hash)
    end
  end

  describe ".decrypt" do
    it "should decrypt a base64 string" do
      Vidibus::Secure.decrypt(encrypted_base64, key).should eql(data)
    end

    it "should decrypt array data from base64 string" do
      Vidibus::Secure.decrypt(encrypted_base64_array, key).should eql(data_array)
    end

    it "should decrypt hash data from base64 string" do
      Vidibus::Secure.decrypt(encrypted_base64_hash, key).should eql(data_hash)
    end

    it "should decrypt a hexadecimal string if :encoding is provided" do
      Vidibus::Secure.decrypt(encrypted_hex, key, :encoding => :hex).should eql(data)
    end

    it "should decrypt a hexadecimal string if encoding settings for :crypt are set to hex" do
      Vidibus::Secure.settings[:crypt][:encoding] = :hex
      Vidibus::Secure.decrypt(encrypted_hex, key).should eql(data)
      Vidibus::Secure.settings[:crypt][:encoding] = :base64
    end

    it "should not fail with nil content" do
      expect {Vidibus::Secure.decrypt(nil, key)}.not_to raise_error
    end

    it "should not fail with blank content" do
      expect {Vidibus::Secure.decrypt('', key)}.not_to raise_error
    end

    it "should not fail with unencrypted content" do
      pending 'really?'
      expect {Vidibus::Secure.decrypt('hello', key)}.not_to raise_error
    end

    it "should return unencrypted content" do
      pending 'really?'
      Vidibus::Secure.decrypt('hello', key).should eql('hello')
    end

    it "should raise a KeyError if given secret key is nil" do
      expect {Vidibus::Secure.sign(data, nil)}.to raise_error(Vidibus::Secure::KeyError)
    end
  end

  describe ".sign_request" do
    it "should not modifiy path for POST and PUT requests" do
      for verb in %w[post put]
        path, params = Vidibus::Secure.sign_request(verb, "/whazzup", {}, key)
        path.should eql("/whazzup")
      end
    end

    it "should raise an InputError if given params is not a Hash" do
      params = %w[1 2 3]
      expect {Vidibus::Secure.sign_request(:post, "/", params, key)}.to raise_error(Vidibus::Secure::InputError, "Given params is not a Hash.")
    end

    context "for requests without body" do
      it "should add signature to params, if no params are given in URI and params argument is a hash" do
        path = "http://vidibus.org/status"
        params = {}
        Vidibus::Secure.sign_request(:get, path, params, key)
        path.should eql("http://vidibus.org/status")
        params.should eql(:sign => "09247a2534f14e57081193ef6834b08843352c796af264f77e76445472dae9ed")
      end

      it "should add signature to URI, if no params are given in URI and params argument nil" do
        path = "http://vidibus.org/status"
        params = nil
        Vidibus::Secure.sign_request(:get, path, params, key)
        path.should eql("http://vidibus.org/status?sign=09247a2534f14e57081193ef6834b08843352c796af264f77e76445472dae9ed")
        params.should be_nil
      end

      it "should add signature to URI, if params argument is a hash, but params are also given in URI" do
        path = "http://vidibus.org/status?feel=good"
        params = {}
        Vidibus::Secure.sign_request(:get, path, params, key)
        path.should eql("http://vidibus.org/status?feel=good&sign=2be2169f27f11ccc519456887838dcbfef54eb461492d60b847d2f01adca9326")
        params.should eql({})
      end

      it "should accept a custom name as signature param" do
        path = "http://vidibus.org/status"
        Vidibus::Secure.sign_request(:get, path, nil, key, "privado")
        path.should eql("http://vidibus.org/status?privado=09247a2534f14e57081193ef6834b08843352c796af264f77e76445472dae9ed")
      end

      it "should create a signature of a given URL" do
        path = "http://vidibus.org/"
        Vidibus::Secure.sign_request(:get, path, nil, key)
        path.should eql("http://vidibus.org/?sign=0ff9ec7056fd6a2b8ea1d2a1f462458719e3cf0b65485c55035ac906fd3d3368")
      end

      it "should create identical signatures for URLs with and without trailing slash" do
        signature = "0ff9ec7056fd6a2b8ea1d2a1f462458719e3cf0b65485c55035ac906fd3d3368"
        Vidibus::Secure.sign_request(:get, "http://vidibus.org", nil, key).first.should match(signature)
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/", nil, key).first.should match(signature)
      end

      it "should create a signature of a given URI" do
        path = "http://vidibus.org/status"
        Vidibus::Secure.sign_request(:get, path, nil, key)
        path.should eql("http://vidibus.org/status?sign=09247a2534f14e57081193ef6834b08843352c796af264f77e76445472dae9ed")
      end

      it "should create identical signatures for URIs with and without trailing slash" do
        signature = "09247a2534f14e57081193ef6834b08843352c796af264f77e76445472dae9ed"
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/status", nil, key).first.should match(signature)
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/status/", nil, key).first.should match(signature)
      end

      it "should create a signature of URI with params" do
        path = "http://vidibus.org/status?type=server"
        Vidibus::Secure.sign_request(:get, path, {}, key)
        path.should eql("http://vidibus.org/status?type=server&sign=ff98a086cca8af703537afe873009f16ea5554826fa5d2665c212a13e44f7da0")
      end

      it "should create identical signatures for URIs with params with and without trailing slash" do
        signature = "ff98a086cca8af703537afe873009f16ea5554826fa5d2665c212a13e44f7da0"
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/status?type=server", {}, key).first.should match(signature)
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/status/?type=server", {}, key).first.should match(signature)
      end

      it "should replace signature in URI with params" do
        path = "http://vidibus.org/status?interval=2&sign=something&type=server"
        Vidibus::Secure.sign_request(:get, path, {}, key)
        path.should eql("http://vidibus.org/status?interval=2&sign=bd66fe642c39d01005090bb9d0a7f62f5c6d563878e6397261ed12bd79bdb92d&type=server")
      end

      it "should replace signature in URI without other params" do
        path = "http://vidibus.org/status?sign=something"
        Vidibus::Secure.sign_request(:get, path, {}, key)
        path.should eql("http://vidibus.org/status?sign=09247a2534f14e57081193ef6834b08843352c796af264f77e76445472dae9ed")
      end

      it "should create identical signatures for URIs with different params order" do
        signature = "116b6628f5b79a42ea9f8eb0e7901404ff641c34baa289dc32b6e2aa57c9281d"
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/status?a=1&b=2", {}, key).first.should match(signature)
        Vidibus::Secure.sign_request(:get, "http://vidibus.org/status/?b=2&a=1", {}, key).first.should match(signature)
      end
    end

    context "for request with body" do
      it "should create a signature of path and params" do
        params = {:some => "thing"}
        Vidibus::Secure.sign_request(:post, "/", params, key)
        params[:sign].should eql("a41b51acf01f7207d250a0a486e60ed385050f848237251efcdb58448e57d20d")
      end

      it "should create a signature of path and nested params" do
        params = {:some => {:nested => "params", :are => {:really => ["serious", "stuff"]}}}
        Vidibus::Secure.sign_request(:post, "/", params, key)
        params[:sign].should eql("3a899c65b9a68fa473e3bc3388b7656538c85498cc63cdcac59eebfe9f68ce07")
      end

      it "should create a different signature of path and nested params with switched keys" do
        params = {:some => {:are => "params", :nested => {:really => ["serious", "stuff"]}}}
        Vidibus::Secure.sign_request(:post, "/", params, key)
        params[:sign].should eql("d28b073381dad3c30bc8f5ff5984d7ff29e04dd95bc9ca04cd1ac95e878e4663")
      end

      it "should replace existing signature" do
        params = {:some => "thing", :sign => "something"}
        Vidibus::Secure.sign_request(:post, "/", params, key)
        params[:sign].should eql("a41b51acf01f7207d250a0a486e60ed385050f848237251efcdb58448e57d20d")
      end

      it "should add signature param as string if params are given as strings" do
        params = {"some" => "thing"}
        Vidibus::Secure.sign_request(:post, "/", params, key)
        params["some"].should eql("thing")
        params["sign"].should_not be_nil
        params[:sign].should be_nil
      end

      it "should add signature param as symbol if params are given as symbols" do
        params = {:some => "thing"}
        Vidibus::Secure.sign_request(:post, "/", params, key)
        params[:some].should eql("thing")
        params[:sign].should_not be_nil
        params["sign"].should be_nil
      end

      it "should add signature param as symbol if no params are given" do
        params = {}
        Vidibus::Secure.sign_request(:post, "/", params, key)
        params[:sign].should_not be_nil
      end
    end
  end

  describe ".verify_request" do
    it "should return true for a valid GET request" do
      path = "http://vidibus.org/status?type=server&sign=ff98a086cca8af703537afe873009f16ea5554826fa5d2665c212a13e44f7da0"
      Vidibus::Secure.verify_request(:get, path, {}, key).should be_true
    end

    it "should return true for a valid GET request even if verb is upcase" do
      path = "http://vidibus.org/status?type=server&sign=ff98a086cca8af703537afe873009f16ea5554826fa5d2665c212a13e44f7da0"
      Vidibus::Secure.verify_request("GET", path, {}, key).should be_true
    end

    it "should return true for a valid GET request if params are given as hash" do
      path = "http://vidibus.org/status"
      params = {:type => "server", :sign => "ff98a086cca8af703537afe873009f16ea5554826fa5d2665c212a13e44f7da0"}
      Vidibus::Secure.verify_request("GET", path, params, key).should be_true
    end

    it "should return false if additional params are given" do
      path = "http://vidibus.org/status?type=server&sign=ff98a086cca8af703537afe873009f16ea5554826fa5d2665c212a13e44f7da0"
      Vidibus::Secure.verify_request("GET", path, { :some => "thing" }, key).should be_false
    end

    it "should return true for a valid POST request with params given as symbols" do
      params = {:some => "thing", :sign => "a41b51acf01f7207d250a0a486e60ed385050f848237251efcdb58448e57d20d"}
      Vidibus::Secure.verify_request(:post, "/", params, key).should be_true
    end

    it "should return true for a valid POST request with params given as string" do
      params = {"some"=>"thing", "sign"=>"a41b51acf01f7207d250a0a486e60ed385050f848237251efcdb58448e57d20d"}
      Vidibus::Secure.verify_request(:post, "/", params, key).should be_true
    end

    it "should return true for a valid POST request with nested params" do
      params = {
        :sign => "3a899c65b9a68fa473e3bc3388b7656538c85498cc63cdcac59eebfe9f68ce07",
        :some => {:nested => "params", :are => {:really => ["serious", "stuff"]}}
      }
      Vidibus::Secure.verify_request(:post, "/", params, key).should be_true
    end

    it "should return true if nested params are given as HashWithIndifferentAccess" do
      params = ActiveSupport::HashWithIndifferentAccess.new({
        :sign => "3a899c65b9a68fa473e3bc3388b7656538c85498cc63cdcac59eebfe9f68ce07",
        :some => {:nested => "params", :are => {:really => ["serious", "stuff"]}}
      })
      Vidibus::Secure.verify_request("POST", "/", params, key).should be_true
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
      path = "http://vidibus.org/status?type=server&sign=ff98a086cca8af703537afe873009f16ea5554826fa5d2665c212a13e44f7da0"
      Vidibus::Secure.verify_request(:delete, path, {}, key).should be_false
    end

    it "should return false if params do not match signature" do
      params = {"sign" => "ff98a086cca8af703537afe873009f16ea5554826fa5d2665c212a13e44f7da0", "some" => "invalid"}
      Vidibus::Secure.verify_request(:post, "/", params, key).should be_false
    end

    it "should return false if signature does not match params" do
      params = {"sign" => "invalid", "some" => "thing"}
      Vidibus::Secure.verify_request(:post, "/", params, key).should be_false
    end

    it "should accept nil params" do
      expect { Vidibus::Secure.verify_request(:get, "", nil, key) }.to_not raise_error
    end
  end
end
