require 'simplecov'
SimpleCov.start

$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'rubygems'
require 'mongoid'
require 'rspec'
require 'rr'
require 'vidibus-secure'
require 'database_cleaner-mongoid'

Mongo::Logger.logger.level = Logger::FATAL

Mongoid.configure do |config|
  config.connect_to('vidibus-secure_test')
end

RSpec.configure do |config|
  config.mock_with :rr
  config.include RR::DSL
  config.before(:each) do
    DatabaseCleaner.strategy = :deletion
    DatabaseCleaner.clean
  end
end
