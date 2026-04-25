require 'httparty'

def fetch_data
  HTTParty.get("https://api.example.com/data")
end
