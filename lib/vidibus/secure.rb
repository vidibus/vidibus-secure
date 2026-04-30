module Vidibus
  module Secure

    GCM_VERSION = 0x02
    CBC_VERSION = 0x01
    GCM_IV_LEN = 12
    GCM_TAG_LEN = 16

    class Error < StandardError; end
    class KeyError < Error; end
    class InputError < Error; end
    class DecryptError < Error; end

    class << self

      attr_accessor :key_resolver

      # Returns the key to use for Mongoid attr_encrypted.
      # Resolver wins over ENV; raises if neither is set.
      def current_key
        resolved = key_resolver&.call
        return resolved if resolved
        return ENV['VIDIBUS_SECURE_KEY'] if ENV['VIDIBUS_SECURE_KEY']
        raise KeyError,
          'No encryption key — set Vidibus::Secure.key_resolver ' \
          'or ENV["VIDIBUS_SECURE_KEY"]'
      end

      # Define default settings for random, sign, and crypt.
      def settings
        @settings ||= {
          random: { length: 50, encoding: :base64 },
          sign:   { algorithm: 'SHA256', encoding: :hex },
          crypt:  { algorithm: 'AES-256-GCM', encoding: :base64 }
        }
      end

      # Returns a truly random string.
      def random(options = {})
        options = settings[:random].merge(options)
        length = options[:length]
        SecureRandom.send(options[:encoding], length)[0, length]
      end

      # Returns signature of given data with given key.
      def sign(data, key, options = {})
        unless key
          raise KeyError.new(
            'Please provide a secret key to sign data with.'
          )
        end
        options = settings[:sign].merge(options)
        digest = OpenSSL::Digest.new(options[:algorithm])
        signature = OpenSSL::HMAC.digest(digest, key, data)
        encode(signature, options)
      end

      # Encrypts given data with given key (AES-256-GCM).
      def encrypt(data, key, options = {})
        unless key
          raise KeyError.new(
            'Please provide a secret key to encrypt data with.'
          )
        end
        options = settings[:crypt].merge(options)
        data = JSON.generate(data) unless data.is_a?(String)
        blob = gcm_encrypt(data, derive_key(key))
        encode(blob, options)
      end

      # Decrypts given data with given key. Dispatches on the
      # version byte (0x02 GCM, 0x01 legacy CBC) and falls back
      # to bare CBC (v4 layout) when no version byte is present.
      def decrypt(data, key, options = {})
        unless key
          raise KeyError.new(
            'Please provide a secret key to decrypt data with.'
          )
        end
        return data if data.nil? || data == ''
        options = settings[:crypt].merge(options)
        raw = decode(data, options)
        plaintext = dispatch_decrypt(raw, key)
        return data unless plaintext
        begin
          JSON.parse(plaintext)
        rescue JSON::ParserError
          plaintext
        end
      end

      # Decrypts a v4 (CBC) ciphertext, forcing the legacy
      # path. Use this only for the rare case where a v4 blob's
      # first byte happens to be 0x01 or 0x02 and would
      # otherwise be misrouted. The blob may carry a 0x01
      # version byte preamble or be bare base64/hex.
      def legacy_decrypt(data, key, options = {})
        unless key
          raise KeyError.new(
            'Please provide a secret key to decrypt data with.'
          )
        end
        return data if data.nil? || data == ''
        options = settings[:crypt].merge(options)
        raw = decode(data, options)
        return nil unless raw && raw != ''
        ct = raw.getbyte(0) == CBC_VERSION ?
          raw.byteslice(1, raw.bytesize - 1) : raw
        plaintext = cbc_decrypt(ct, key)
        begin
          JSON.parse(plaintext)
        rescue JSON::ParserError
          plaintext
        end
      end

      # Signs request.
      def sign_request(verb, path, params, key, signature_param = nil)
        default_signature_param = :sign
        params_given = !!params
        if params_given && !params.is_a?(Hash)
          raise InputError.new('Given params is not a Hash.')
        end
        params = {} unless params_given
        signature_param ||=
          if params_given && params.keys.first.is_a?(String)
            default_signature_param.to_s
          else
            default_signature_param
          end

        uri = URI.parse(path)
        path_params = Rack::Utils.parse_nested_query(uri.query)
        uri.query = nil

        _verb = verb.to_s.downcase
        _params = params.merge(path_params).
          except(signature_param.to_s, signature_param.to_s.to_sym)

        signature_string = [
          _verb,
          uri.to_s.gsub(/\/+$/, ''),
          _params.any? ? params_identifier(_params) : ''
        ].join('|')

        signature = sign(signature_string, key)

        if %w[post put].include?(_verb) ||
            (params_given && path_params.empty?)
          params[signature_param] = signature
        else
          unless path.gsub!(/(#{signature_param}=)[^&]+/,
                            "\\1#{signature}")
            glue = path.match(/\?/) ? '&' : '?'
            path << "#{glue}#{signature_param}=#{signature}"
          end
        end
        [path, params]
      end

      # Verifies that given request is valid.
      def verify_request(verb, path, params, key, signature_param = nil)
        params ||= {}
        _path = path.dup
        _params = params.dup
        sign_request(verb, _path, _params, key, signature_param)
        path == _path && params == _params
      end

      protected

      # Ensure the AES key is exactly 32 bytes. SHA256-derive
      # otherwise (per 5.0 — no more pkcs5_keyivgen for GCM).
      def derive_key(key)
        return key if key.is_a?(String) && key.bytesize == 32
        OpenSSL::Digest::SHA256.new(key.to_s).digest
      end

      def gcm_encrypt(plaintext, key)
        cipher = OpenSSL::Cipher.new('AES-256-GCM')
        cipher.encrypt
        cipher.key = key
        iv = cipher.random_iv # 12 bytes by default for GCM
        ct = cipher.update(plaintext) + cipher.final
        tag = cipher.auth_tag(GCM_TAG_LEN)
        ([GCM_VERSION].pack('C') + iv + tag + ct).b
      end

      def gcm_decrypt(raw, key)
        body = raw.byteslice(1, raw.bytesize - 1) || ''
        if body.bytesize < GCM_IV_LEN + GCM_TAG_LEN
          raise DecryptError, 'GCM payload too short'
        end
        iv  = body.byteslice(0, GCM_IV_LEN)
        tag = body.byteslice(GCM_IV_LEN, GCM_TAG_LEN)
        ct  = body.byteslice(GCM_IV_LEN + GCM_TAG_LEN,
                             body.bytesize - GCM_IV_LEN - GCM_TAG_LEN)
        cipher = OpenSSL::Cipher.new('AES-256-GCM')
        cipher.decrypt
        cipher.key = key
        cipher.iv = iv
        cipher.auth_tag = tag
        cipher.update(ct.to_s) + cipher.final
      rescue OpenSSL::Cipher::CipherError => e
        raise DecryptError, "GCM decryption failed: #{e.message}"
      end

      def cbc_decrypt(ct, key)
        cipher = OpenSSL::Cipher.new('AES-256-CBC')
        cipher.decrypt
        cipher.pkcs5_keyivgen(OpenSSL::Digest::SHA512.new(key).digest)
        cipher.update(ct) + cipher.final
      rescue OpenSSL::Cipher::CipherError => e
        raise DecryptError, "CBC decryption failed: #{e.message}"
      end

      def dispatch_decrypt(raw, key)
        return nil unless raw && raw != ''
        case raw.getbyte(0)
        when GCM_VERSION
          gcm_decrypt(raw, derive_key(key))
        when CBC_VERSION
          cbc_decrypt(raw.byteslice(1, raw.bytesize - 1), key)
        else
          # bare CBC (v4 layout, no version byte)
          cbc_decrypt(raw, key)
        end
      end

      def encode(data, options = {})
        return unless data
        if options[:encoding] == :hex
          data.unpack('H*').join
        elsif options[:encoding] == :base64
          [data].pack('m*')
        end
      end

      def decode(data, options = {})
        return unless data
        if options[:encoding] == :hex
          [data].pack('H*')
        elsif options[:encoding] == :base64
          data.unpack('m*').join
        end
      end

      # Returns an identifier string from given params input.
      #
      # Example:
      #   {:some=>{:nested=>{:really=>["serious", "stuff"]}, :are=>"params"}}
      #   # => 1:some:2:are:params|2:nested:3:really:4:serious:|4:stuff:
      #
      def params_identifier(params, level = 1)
        array = []
        for key, value in params
          if value.is_a?(Array) || value.is_a?(Hash)
            value = params_identifier(value, level + 1)
          end
          array << "#{level}:#{key}:#{value}"
        end
        array.sort.join('|')
      end
    end
  end
end
