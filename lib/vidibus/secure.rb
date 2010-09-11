require "openssl"
require "active_support/secure_random"
require "rack"
require "uri"

module Vidibus
  module Secure
    
    class KeyError < StandardError; end
    
    class << self
      
      # Define default settings for random, sign, and crypt.
      def settings
        @settings ||= { 
          :random => { :length => 50, :encoding => :base64 },
          :sign => { :algorithm => "SHA256", :encoding => :hex },
          :crypt => { :algorithm => "AES-256-CBC", :encoding => :base64 }
        }
      end
      
      # Returns a truly random string.
      # Now it is not much more than an interface for ActiveSupport::SecureRandom, 
      # but that might change over time.
      # 
      # Options:
      #   :length     Length of string to generate
      #   :encoding   Encoding of string; hex or base64
      # 
      # Keep in mind that a hexadecimal string is less secure
      # than a base64 encoded string with the same length!
      # 
      def random(options = {})
        options = settings[:random].merge(options)
        length = options[:length]
        ActiveSupport::SecureRandom.send(options[:encoding], length)[0,length]
      end
      
      # Returns signature of given data with given key.
      def sign(data, key, options = {})
        raise KeyError.new("Please provide a secret key to sign data with.") unless key
        options = settings[:sign].merge(options)
        digest = OpenSSL::Digest::Digest.new(options[:algorithm])
        signature = OpenSSL::HMAC.digest(digest, key, data)
        encode(signature, options)
      end
      
      # Encrypts given data with given key.
      def encrypt(data, key, options = {})
        raise KeyError.new("Please provide a secret key to encrypt data with.") unless key
        options = settings[:crypt].merge(options)
        encrypted_data = crypt(:encrypt, data, key, options)
        encode(encrypted_data, options)
      end
      
      # Decrypts given data with given key.
      def decrypt(data, key, options = {})
        raise KeyError.new("Please provide a secret key to decrypt data with.") unless key
        options = settings[:crypt].merge(options)
        decoded_data = decode(data, options)
        crypt(:decrypt, decoded_data, key, options)
      end
      
      # Signs request.
      def sign_request(verb, path, params, key, signature_param = nil)
        default_signature_param = :sign
        params_given = params and params.is_a?(Hash)
        params = {} unless params_given
        signature_param ||= params.keys.first.is_a?(String) ? default_signature_param.to_s : default_signature_param
        
        uri = URI.parse(path)
        path_params = Rack::Utils.parse_query(uri.query)
        uri.query = nil
        
        _verb = verb.to_s.downcase
        _uri = uri.to_s.gsub(/\/+$/, "")
        _params = (params.merge(path_params)).except(signature_param.to_s, signature_param.to_s.to_sym)        
        _params = _params.any? ? _params.to_a.sort{|a,b| a.to_s <=> b.to_s}.flatten.join("|") : ""

        signature = sign("#{_verb}|#{_uri}|#{_params}", key)
        
        if %w[post put].include?(_verb) or (params_given and path_params.empty?)
          params[signature_param] = signature
        else
          unless path.gsub!(/(#{signature_param}=)[^&]+/, "\\1#{signature}")
            glue = path.match(/\?/) ? "&" : "?"
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
        return (path == _path and params == _params)
      end
      
      protected
      
      def crypt(cipher_method, data, key, options = {})
        cipher = OpenSSL::Cipher::Cipher.new(options[:algorithm])
        digest = OpenSSL::Digest::SHA512.new(key).digest
        cipher.send(cipher_method)
        cipher.pkcs5_keyivgen(digest)
        result = cipher.update(data)
        result << cipher.final
      end
      
      def encode(data, options = {})
        if options[:encoding] == :hex
          data.unpack("H*").to_s
        elsif options[:encoding] == :base64
          [data].pack("m*")
        end
      end
      
      def decode(data, options = {})
        if options[:encoding] == :hex
          [data].pack("H*")
        elsif options[:encoding] == :base64
          data.unpack("m*").to_s
        end
      end
    end
  end
end
