module Vidibus
  module Secure
    module Extensions
      
      # Contains extensions of ApplicationController.
      module Controller
        extend ActiveSupport::Concern

        included do
          helper_method :valid_request?
        end
        
        # Generates a signature of a request path.
        # Will use the current request.fullpath unless an URI is given.
        #
        # The given URI will be decomposed into path and request params. 
        # A given +signature_param+ will be removed, all remaining params 
        # will be ordered alphabetically.
        #
        # Usage:
        #
        #   valid_request?("mysecret")
        #   valid_request?("mysecret", :uri => "http://...", :method => "get", :params => {})
        # 
        def valid_request?(secret, options = {})
          method = options.delete(:method) || request.method
          uri = options.delete(:uri) || request.protocol + request.host_with_port + request.fullpath
          params = options.delete(:params) || request.params
          Vidibus::Secure.verify_request(method, uri, params, secret)
        end
      end
    end
  end
end
