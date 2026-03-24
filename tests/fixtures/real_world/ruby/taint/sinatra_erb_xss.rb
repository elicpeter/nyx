require 'sinatra'

get '/greet' do
  name = params[:name]
  erb "<p>Hello #{name}</p>"
end
