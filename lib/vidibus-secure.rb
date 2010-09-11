require "vidibus-core_extensions"

$:.unshift(File.join(File.dirname(__FILE__), "..", "lib", "vidibus"))
require "secure"
require "secure/mongoid"
require "secure/extensions"