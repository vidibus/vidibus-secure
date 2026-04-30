# Vidibus::Secure

Allows encryption and signing of requests and storing encrypted data within Mongoid documents.

This gem is part of [Vidibus](http://vidibus.org), an open source toolset for building distributed (video) applications.


## Installation

Add `gem "vidibus-secure"` to your Gemfile. Then call `bundle install` on your console.

If you want to use Vidibus::Secure::Mongoid on your models, you should generate an initializer to set an unique encryption key by calling `rails generate vidibus_secure_key`, also on your console.


## Usage

```ruby
class MyModel
  include Mongoid::Document
  include Vidibus::Secure::Mongoid

  attr_encrypted :my_secret
end
```

Defining `attr_encrypted :my_secret` creates a setter and a getter for `my_secret`. You can use it like a normal attribute, but the value is stored encrypted with AES-256-GCM.


## Encryption key

The Mongoid integration looks up the encryption key on every read and write. The lookup order is:

1. `Vidibus::Secure.key_resolver` — a callable (lambda or proc) returning the key.
2. `ENV["VIDIBUS_SECURE_KEY"]` — fallback for simple deployments.

If neither is set, `Vidibus::Secure::KeyError` is raised.

The key passed in IS the AES key (32 bytes). Anything shorter or longer is reduced to 32 bytes via `SHA256(key)`.


## Per-request key resolution

For multi-tenant apps that need a different key per request (e.g. master DB vs. tenant DB), set a resolver early in the request lifecycle:

```ruby
# config/initializers/vidibus_secure.rb
Vidibus::Secure.key_resolver = -> { Current.tenant&.encryption_key }
```

The resolver is consulted on every encrypted read/write, so swapping `Current.tenant` mid-request swaps the key. Direct callers of `Vidibus::Secure.encrypt(data, key)` still pass the key explicitly — the resolver only affects the Mongoid integration.


## Storage format and migration

New writes use AES-256-GCM with the layout `[0x02][12B IV][16B tag][ciphertext]` (then base64- or hex-encoded). Existing v4 (CBC) ciphertexts continue to decrypt transparently. To migrate stored values to the new format, iterate your records and reassign each encrypted attribute:

```ruby
MyModel.each do |m|
  m.update(my_secret: m.my_secret)
end
```

Tampered ciphertexts raise `Vidibus::Secure::DecryptError` rather than returning garbage — that's the GCM auth-tag win.

A v4 ciphertext whose first byte happens to be `0x01` or `0x02` (≈0.78% of legacy blobs) will be misrouted by the version-byte dispatch and raise `DecryptError`. If you hit that during migration, force the legacy path:

```ruby
Vidibus::Secure.legacy_decrypt(blob, key)
```


## Copyright

&copy; 2010-2026 Andre Pankratz. See LICENSE for details.
