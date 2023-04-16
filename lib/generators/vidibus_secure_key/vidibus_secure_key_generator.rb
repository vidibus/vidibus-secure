class VidibusSecureKeyGenerator < Rails::Generators::Base
  desc 'Creates secure key to be stored as ENV["VIDIBUS_SECURE_KEY"]'

  puts "\nAdd VIDIBUS_SECURE_KEY to your env file like ~/.bashrc, /etc/profile or ~/.zprofile"
  key = %(export VIDIBUS_SECURE_KEY=#{Vidibus::Secure.random(:encoding => :base64, :length => 100)})
  puts key
end
