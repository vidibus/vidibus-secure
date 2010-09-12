class VidibusSecureKeyGenerator < Rails::Generators::Base
  desc 'Generates an initializer that sets ENV["VIDIBUS_SECURE_KEY"]'

  def create_initializer
    create_file "config/initializers/vidibus_secure_key.rb" do
      %(# This is a secret key for encrypting values of field defined by attr_encrypted.\n) +
      %(# Do not change this encryption key! Otherwise you will not be able to decrypt data already stored in your database.\n) +
      %(ENV["VIDIBUS_SECURE_KEY"] = "#{Vidibus::Secure.random(:encoding => :base64, :length => 100)}")
    end
  end
end
