require 'cgi'
require 'sinatra'

def clean_input(s)
  CGI.escapeHTML(s)
end

get '/profile' do
  name = params['name']
  safe = clean_input(name)
  "<h1>#{safe}</h1>"
end
