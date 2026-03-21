require 'net/http'
require 'uri'

def health_check
  uri = URI.parse("https://api.example.com/health")
  Net::HTTP.get(uri)
end
