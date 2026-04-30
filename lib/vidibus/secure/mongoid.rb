module Vidibus
  module Secure
    module Mongoid
      extend ActiveSupport::Concern

      module ClassMethods

        # Defines encrypted attributes. The encryption key is
        # resolved on every read and write via
        # Vidibus::Secure.current_key, so callers can swap keys
        # per request (e.g. tenant-scoped DB context).
        def attr_encrypted(*args)
          args.extract_options!
          args.each do |attr|
            encrypted_field = "#{attr}_encrypted"
            field encrypted_field, type: BSON::Binary

            define_method("#{attr}=") do |value|
              if value.nil?
                self[encrypted_field] = nil
              else
                blob = Vidibus::Secure.encrypt(
                  value, Vidibus::Secure.current_key
                )
                self[encrypted_field] = BSON::Binary.new(blob)
              end
            end

            define_method(attr) do
              raw = self[encrypted_field]
              return nil unless raw
              data = raw.respond_to?(:data) ? raw.data : raw
              Vidibus::Secure.decrypt(data, Vidibus::Secure.current_key)
            end
          end
        end
      end
    end
  end
end
