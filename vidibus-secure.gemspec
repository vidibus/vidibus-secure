# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib/', __FILE__)
$:.unshift lib unless $:.include?(lib)

require 'vidibus/secure/version'

Gem::Specification.new do |s|
  s.name        = 'vidibus-secure'
  s.version     = Vidibus::Secure::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = 'Andre Pankratz'
  s.email       = 'andre@vidibus.com'
  s.homepage    = 'https://github.com/vidibus/vidibus-secure'
  s.summary     = 'Security tools for Vidibus applications'
  s.description = 'Allows encryption and signing of requests and storing encrypted data within Mongoid documents.'
  s.license     = 'MIT'

  s.required_rubygems_version = '>= 1.3.6'
  s.rubyforge_project         = 'vidibus-secure'

  s.add_dependency 'rack'
  s.add_dependency 'mongoid'
  s.add_dependency 'activesupport'
  s.add_dependency 'json'
  s.add_dependency 'vidibus-core_extensions'

  s.add_development_dependency 'bundler', '>= 1.0.0'
  s.add_development_dependency 'rake'
  s.add_development_dependency 'rdoc'
  s.add_development_dependency 'rspec', '~> 2'
  s.add_development_dependency 'rr'
  s.add_development_dependency 'simplecov'
  s.add_development_dependency 'actionpack'
  s.add_development_dependency 'database_cleaner'

  s.files = Dir.glob('{lib,app,config}/**/*') + %w[LICENSE README.md Rakefile]
  s.require_path = 'lib'
end
