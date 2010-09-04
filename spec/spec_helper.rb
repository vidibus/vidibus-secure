$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), "..", "lib"))

require "rubygems"
require "mongoid"
require "rspec"
require "rr"
require "vidibus-secure"

Mongoid.configure do |config|
  name = "vidibus-secure_test"
  host = "localhost"
  config.master = Mongo::Connection.new.db(name)
end

RSpec.configure do |config|
  config.mock_with :rr
  config.after :suite do
    Mongoid.master.collections.select {|c| c.name !~ /system/ }.each(&:drop)
  end
end
