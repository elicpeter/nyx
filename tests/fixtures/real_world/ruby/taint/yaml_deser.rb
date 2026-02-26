require 'sinatra'
require 'yaml'

post '/parse' do
  data = request.body.read
  config = YAML.load(data)
  config.to_s
end

post '/parse-safe' do
  data = request.body.read
  config = YAML.safe_load(data)
  config.to_s
end
