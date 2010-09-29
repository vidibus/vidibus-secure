require "ostruct"
require "spec_helper"
require "action_controller"

class Controller < ActionController::Base; end

describe "Vidibus::Secure::Extensions::Controller" do
  let(:controller) { Controller.new }
  let(:secret) { "mysecret" }

  before do
    stub(controller).request do
      @request ||= begin
        Struct.new("Request", :protocol, :host_with_port, :fullpath, :method, :params) unless defined?(Struct::Request)
        Struct::Request.new("http://", "vidibus.org", "/", "get", {})
      end
    end
  end

  describe "#valid_request?" do
    it "should available to controllers that stem from ActionController::Base" do
      controller.should respond_to(:valid_request?)
    end

    it "should build URI from request object if no :uri is provided" do
      mock(controller.request).protocol {"http://"}
      mock(controller.request).host_with_port {"vidibus.org"}
      mock(controller.request).fullpath {"/"}
      controller.valid_request?(secret, :method => "get", :params => {})
    end

    it "should use request.method if no :method is provided" do
      mock(controller.request).method {"get"}
      controller.valid_request?(secret, :uri => "something", :params => {})
    end

    it "should extract params from request uri unless params are provided" do
      mock(Rack::Utils).parse_query("with=params").twice {{}}
      controller.valid_request?(secret, :uri => "something/?with=params", :method => "get")
    end

    it "should use given params" do
      dont_allow(controller).request
      controller.valid_request?(secret, :method => "get", :uri => "something", :params => {})
    end

    it "should return true for valid requests" do
      params = {}
      Vidibus::Secure.sign_request(:get, "http://vidibus.org/", params, secret)
      controller.request.fullpath = "?sign=#{params[:sign]}"
      controller.valid_request?(secret).should be_true
    end

    it "should use given custom params" do
      params = { :action => "index", :controller => "application", :id => "12" }
      Vidibus::Secure.sign_request(:get, "http://vidibus.org/", params, secret)
      controller.valid_request?(secret, :params => params).should be_true
    end

    it "should call Vidibus::Secure.verify_request" do
      mock(Vidibus::Secure).verify_request("get", "http://vidibus.org/", {}, secret)
      controller.valid_request?(secret)
    end
  end
end
