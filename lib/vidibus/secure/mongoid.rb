module Vidibus
  module Secure
    module Mongoid
      extend ActiveSupport::Concern
      module ClassMethods

        # Sets encrypted attributes.
        def attr_encrypted(*args)
          key = ENV["VIDIBUS_SECURE_KEY"]
          options = args.extract_options!
          for field in args

            # Define Mongoid field
            encrypted_field = "#{field}_encrypted"
            self.send(:field, encrypted_field, :type => Moped::BSON::Binary)

            # Define setter
            class_eval <<-EOV
              def #{field}=(value)
                self.#{encrypted_field} = value ? Vidibus::Secure.encrypt(value, "#{key}") : nil
              end
            EOV

            # Define getter
            class_eval <<-EOV
              def #{field}
                Vidibus::Secure.decrypt(#{encrypted_field}, "#{key}") if #{encrypted_field}
              end
            EOV
          end
        end
      end
    end
  end
end
