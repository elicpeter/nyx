require 'httparty'

def send_data(params)
  url = params[:url]
  HTTParty.post(url, body: { key: 'value' })
end
