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
      controller.valid_request?(secret, :method => "get", :params => {})
    end
    
    it "should use request.method if no :method is provided" do
      controller.valid_request?(secret, :uri => "something", :params => {})
    end
    
    it "should use request.params if no :params are provided" do
      controller.valid_request?(secret, :uri => "something", :method => "get")
    end
    
    it "should call Vidibus::Secure.verify_request" do
      mock(Vidibus::Secure).verify_request("get", "http://vidibus.org/", {}, secret)
      controller.valid_request?(secret)
    end
  end
end
