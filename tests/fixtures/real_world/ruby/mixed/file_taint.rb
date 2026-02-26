require 'sinatra'

get '/read' do
  path = params[:path]
  f = File.open(path, 'r')
  data = f.read
  # taint: path is user input
  # state: f leaked
  data
end
