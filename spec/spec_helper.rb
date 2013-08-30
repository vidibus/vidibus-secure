require 'simplecov'
SimpleCov.start

$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'rubygems'
require 'mongoid'
require 'rspec'
require 'rr'
require 'vidibus-secure'

Mongoid.configure do |config|
  config.connect_to('vidibus-secure_test')
end

RSpec.configure do |config|
  config.mock_with :rr
  config.after :suite do
    Mongoid::Sessions.default.collections.
      select {|c| c.name !~ /system/}.each(&:drop)
  end
end
