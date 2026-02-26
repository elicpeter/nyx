require 'sinatra'
require 'base64'

post '/load' do
  data = params[:data]
  decoded = Base64.decode64(data)
  obj = Marshal.load(decoded)
  obj.to_s
end
