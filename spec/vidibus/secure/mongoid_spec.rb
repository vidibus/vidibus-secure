require "spec_helper"

ENV["VIDIBUS_SECURE_KEY"] = "c4l60HC/lyerr2VEnrP7s2YAldyZGfIBePUzCl+tBsTs1EWJOc8dEJ7F2Vty7KPEeRuBWGxZHVAbku8pLo+UvXRpLcRiF7lxKiKl"

class Model
  include Mongoid::Document
  include Vidibus::Secure::Mongoid
  attr_encrypted :my_secret, :another_secret
end

describe "Vidibus::Secure::Mongoid" do
  let(:model) { Model.new }
  let(:secret) { "My name is Bond." }
  let(:encrypted_secret) { "+PlBG1ChiqUAYMrHlJzDL4NwXHtGBIUm/KQ2ZWfwxjM=\n" }

  it "should add a field :my_secret_encrypted" do
    model.should respond_to(:my_secret_encrypted)
  end

  it "should add a setter for :my_secret" do
    model.should respond_to(:my_secret=)
  end

  it "should add a getter for :my_secret" do
    model.should respond_to(:my_secret)
  end

  it "should add a field :another_secret_encrypted" do
    model.should respond_to(:another_secret_encrypted)
  end

  it "should add a setter for :another_secret" do
    model.should respond_to(:another_secret=)
  end

  it "should add a getter for :another_secret" do
    model.should respond_to(:another_secret)
  end

  describe "#my_secret=" do
    it "should set :my_secret_encrypted" do
      model.my_secret_encrypted.should be_nil
      model.my_secret = "my_secret"
      model.my_secret_encrypted.should_not be_nil
    end

    it "should encrypt a given value" do
      model.my_secret = secret
      model.my_secret_encrypted.should eql(encrypted_secret)
    end

    it "should be persistent" do
      model.my_secret = secret
      model.save!
      model.reload
      model.my_secret_encrypted.should eql(encrypted_secret)
    end

    it "should not encrypt nil" do
      model.my_secret = nil
      model.my_secret_encrypted.should eql(nil)
    end
  end

  describe "#my_secret" do
    it "should get :my_secret_encrypted" do
      model.my_secret.should be_nil
      model.my_secret_encrypted = encrypted_secret
      model.my_secret.should_not be_nil
    end

    it "should decrypt value of :my_secret_encrypted" do
      model.my_secret_encrypted = encrypted_secret
      model.my_secret.should eql(secret)
    end

    it "should be persistent" do
      model.my_secret_encrypted = encrypted_secret
      model.save!
      model.reload
      model.my_secret.should eql(secret)
    end

    it "should not decrypt nil" do
      model.my_secret_encrypted = nil
      model.my_secret.should eql(nil)
    end
  end
end
