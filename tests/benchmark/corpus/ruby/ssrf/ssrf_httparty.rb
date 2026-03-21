require 'httparty'

def fetch_url(params)
  url = params[:url]
  HTTParty.get(url)
end
