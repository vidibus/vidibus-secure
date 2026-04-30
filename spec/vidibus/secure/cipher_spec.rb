require 'spec_helper'

describe 'Vidibus::Secure cipher (5.0)' do
  let(:key) { 'a' * 32 }
  let(:short_key) { 'short' }
  let(:data) { 'My name is Bond. You know the rest.' }
  let(:data_array) { ['Bond', 'James'] }
  let(:data_hash) { {'name' => 'James Bond'} }

  # v4 fixture: bare base64, AES-256-CBC, pkcs5_keyivgen(SHA512(key))
  let(:legacy_key) do
    '8KTbTanrBTQ5c8CjANpJQjPWcIstFxq/uFIUQBF3gRnzt' \
      'M565xIfe8MStVcLilbEhjYwfZiD4lFWINF22Aw8gVEbk' \
      'Sf2rLN0fnuO9YtNqFLQU6m/OldO5JbsBJPCwuzsPYmZ1w=='
  end
  let(:legacy_v4_base64) do
    "hXUWa3gHRpYr/Fi2qm9xdTyZg7NSpYq8X2p1EL+/wff" \
      "Ug9IeIjVbSvyUYAvyTLbc\n"
  end
  let(:legacy_v4_plaintext) { 'My name is Bond. You know the rest.' }

  describe '.encrypt' do
    it 'round-trips a string via base64' do
      blob = Vidibus::Secure.encrypt(data, key)
      expect(Vidibus::Secure.decrypt(blob, key)).to eq(data)
    end

    it 'round-trips an array via base64' do
      blob = Vidibus::Secure.encrypt(data_array, key)
      expect(Vidibus::Secure.decrypt(blob, key)).to eq(data_array)
    end

    it 'round-trips a hash via base64' do
      blob = Vidibus::Secure.encrypt(data_hash, key)
      expect(Vidibus::Secure.decrypt(blob, key)).to eq(data_hash)
    end

    it 'round-trips via hex encoding' do
      blob = Vidibus::Secure.encrypt(data, key, encoding: :hex)
      expect(Vidibus::Secure.decrypt(blob, key, encoding: :hex)).
        to eq(data)
    end

    it 'produces a different ciphertext on every call (random IV)' do
      a = Vidibus::Secure.encrypt(data, key)
      b = Vidibus::Secure.encrypt(data, key)
      expect(a).not_to eq(b)
    end

    it 'emits the 0x02 version byte as the first plaintext byte' do
      blob = Vidibus::Secure.encrypt(data, key)
      raw = blob.unpack('m*').join
      expect(raw.bytes.first).to eq(0x02)
    end

    it 'derives a 32-byte key via SHA256 if key is not 32 bytes' do
      blob = Vidibus::Secure.encrypt(data, short_key)
      expect(Vidibus::Secure.decrypt(blob, short_key)).to eq(data)
    end
  end

  describe '.decrypt' do
    it 'raises DecryptError on tampered ciphertext' do
      blob = Vidibus::Secure.encrypt(data, key)
      raw = blob.unpack('m*').join.dup
      # flip a byte well inside the ciphertext (skip version+iv+tag)
      raw.setbyte(35, raw.getbyte(35) ^ 0x01)
      tampered = [raw].pack('m*')
      expect { Vidibus::Secure.decrypt(tampered, key) }.
        to raise_error(Vidibus::Secure::DecryptError)
    end

    it 'raises DecryptError on wrong key' do
      blob = Vidibus::Secure.encrypt(data, key)
      expect { Vidibus::Secure.decrypt(blob, 'b' * 32) }.
        to raise_error(Vidibus::Secure::DecryptError)
    end

    it 'decrypts legacy bare-base64 v4 CBC blobs' do
      result = Vidibus::Secure.decrypt(legacy_v4_base64, legacy_key)
      expect(result).to eq(legacy_v4_plaintext)
    end

    it 'decrypts 0x01-prefixed CBC blobs' do
      # build a 0x01-prefixed CBC blob using the legacy code path
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.pkcs5_keyivgen(
        OpenSSL::Digest::SHA512.new(legacy_key).digest
      )
      ct = cipher.update(legacy_v4_plaintext) + cipher.final
      blob = [("\x01".b + ct)].pack('m*')
      expect(Vidibus::Secure.decrypt(blob, legacy_key)).
        to eq(legacy_v4_plaintext)
    end

    it 'returns nil for nil input' do
      expect { Vidibus::Secure.decrypt(nil, key) }.not_to raise_error
    end

    it 'returns nil for blank input' do
      expect { Vidibus::Secure.decrypt('', key) }.not_to raise_error
    end
  end

  describe '.legacy_decrypt' do
    it 'decrypts a v4 bare-base64 blob' do
      result = Vidibus::Secure.legacy_decrypt(legacy_v4_base64, legacy_key)
      expect(result).to eq(legacy_v4_plaintext)
    end

    it 'decrypts a v4 blob even when first byte collides with 0x02' do
      iv_digest = OpenSSL::Digest::SHA512.new(legacy_key).digest
      blob = nil
      collision_pt = nil
      5000.times do |i|
        pt = "p#{i}"
        cipher = OpenSSL::Cipher.new('AES-256-CBC')
        cipher.encrypt
        cipher.pkcs5_keyivgen(iv_digest)
        ct = cipher.update(pt) + cipher.final
        if ct.getbyte(0) == 0x02
          blob = [ct].pack('m*')
          collision_pt = pt
          break
        end
      end
      raise 'expected to find a 0x02-first-byte collision' unless blob

      # plain decrypt would misroute to GCM and raise
      expect { Vidibus::Secure.decrypt(blob, legacy_key) }.
        to raise_error(Vidibus::Secure::DecryptError)

      # legacy_decrypt rescues us
      expect(Vidibus::Secure.legacy_decrypt(blob, legacy_key)).
        to eq(collision_pt)
    end

    it 'parses JSON output (arrays/hashes)' do
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.pkcs5_keyivgen(
        OpenSSL::Digest::SHA512.new(legacy_key).digest
      )
      ct = cipher.update('[1,2,3]') + cipher.final
      blob = [ct].pack('m*')
      expect(Vidibus::Secure.legacy_decrypt(blob, legacy_key)).
        to eq([1, 2, 3])
    end

    it 'returns nil for nil input' do
      expect(Vidibus::Secure.legacy_decrypt(nil, legacy_key)).to be_nil
    end

    it 'raises KeyError if key is nil' do
      expect { Vidibus::Secure.legacy_decrypt('xx', nil) }.
        to raise_error(Vidibus::Secure::KeyError)
    end
  end
end
