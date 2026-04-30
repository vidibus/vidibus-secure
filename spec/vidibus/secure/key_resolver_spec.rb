require 'spec_helper'

describe 'Vidibus::Secure.key_resolver' do
  before do
    @prev_resolver = Vidibus::Secure.key_resolver
    @prev_env = ENV['VIDIBUS_SECURE_KEY']
  end

  after do
    Vidibus::Secure.key_resolver = @prev_resolver
    ENV['VIDIBUS_SECURE_KEY'] = @prev_env
  end

  describe '.current_key' do
    it 'returns the resolver result when set' do
      Vidibus::Secure.key_resolver = -> { 'resolver-key' }
      ENV['VIDIBUS_SECURE_KEY'] = 'env-key'
      expect(Vidibus::Secure.current_key).to eq('resolver-key')
    end

    it 'falls back to ENV when resolver is nil' do
      Vidibus::Secure.key_resolver = nil
      ENV['VIDIBUS_SECURE_KEY'] = 'env-key'
      expect(Vidibus::Secure.current_key).to eq('env-key')
    end

    it 'falls back to ENV when resolver returns nil' do
      Vidibus::Secure.key_resolver = -> { nil }
      ENV['VIDIBUS_SECURE_KEY'] = 'env-key'
      expect(Vidibus::Secure.current_key).to eq('env-key')
    end

    it 'raises KeyError when resolver and ENV are both unset' do
      Vidibus::Secure.key_resolver = nil
      ENV.delete('VIDIBUS_SECURE_KEY')
      expect { Vidibus::Secure.current_key }.
        to raise_error(Vidibus::Secure::KeyError)
    end
  end
end
