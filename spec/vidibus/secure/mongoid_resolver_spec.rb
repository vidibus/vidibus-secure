require 'spec_helper'

class ResolverModel
  include Mongoid::Document
  include Vidibus::Secure::Mongoid
  attr_encrypted :token
end

describe 'Vidibus::Secure::Mongoid with key_resolver' do
  before do
    @prev_resolver = Vidibus::Secure.key_resolver
    @prev_env = ENV['VIDIBUS_SECURE_KEY']
    ENV.delete('VIDIBUS_SECURE_KEY')
  end

  after do
    Vidibus::Secure.key_resolver = @prev_resolver
    ENV['VIDIBUS_SECURE_KEY'] = @prev_env
  end

  it 'resolves the key on every write/read' do
    key_a = 'a' * 32
    key_b = 'b' * 32
    current = key_a
    Vidibus::Secure.key_resolver = -> { current }

    m = ResolverModel.new
    m.token = 'first'
    blob_a = m.token_encrypted.data
    expect(m.token).to eq('first')

    current = key_b
    m.token = 'second'
    blob_b = m.token_encrypted.data
    expect(m.token).to eq('second')

    # decrypting blob_a now requires the original key — it must
    # NOT have been baked in at definition time
    expect {
      current = key_a
      n = ResolverModel.new
      n.token_encrypted = BSON::Binary.new(blob_a)
      expect(n.token).to eq('first')
    }.not_to raise_error

    current = key_b
    n2 = ResolverModel.new
    n2.token_encrypted = BSON::Binary.new(blob_b)
    expect(n2.token).to eq('second')
  end

  it 'raises KeyError if no key is configured' do
    Vidibus::Secure.key_resolver = nil
    expect { ResolverModel.new.token = 'x' }.
      to raise_error(Vidibus::Secure::KeyError)
  end
end
