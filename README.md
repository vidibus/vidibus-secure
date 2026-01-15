# Vidibus::Secure

Allows encryption and signing of requests and storing encrypted data within Mongoid documents.

This gem is part of [Vidibus](http://vidibus.org), an open source toolset for building distributed (video) applications.


## Installation

Add `gem "vidibus-secure"` to your Gemfile. Then call `bundle install` on your console.

If you want to use Vidibus::Secure::Mongoid on your models, you should generate an initializer to set an unique encryption key by calling `rails generate vidibus_secure_key`, also on your console.


## Usage

```
class MyModel
  include Mongoid::Document
  include Vidibus::Secure::Mongoid

  attr_encrypted :my_secret
```

Defining `attr_encrypted :my_secret` will create setter and getter for `my_secret`. You can use it like normal. But it will be stored encrypted.


## Copyright

&copy; 2010-2026 Andre Pankratz. See LICENSE for details.
