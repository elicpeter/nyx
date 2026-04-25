require 'net/http'
require 'uri'

def fetch_url(params)
  url = params[:url]
  uri = URI.parse(url)
  Net::HTTP.get(uri)
end
