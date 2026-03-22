require 'net/http'

def fetch_url(params)
  url = params[:url]
  Net::HTTP.get(URI(url))
end
