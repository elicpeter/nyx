require 'sinatra'

get '/run' do
  cmd = params[:command]
  result = `#{cmd}`
  result
end
