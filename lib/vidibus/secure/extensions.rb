require "vidibus/secure/extensions/controller"

ActiveSupport.on_load(:action_controller) do
  include Vidibus::Secure::Extensions::Controller
end
