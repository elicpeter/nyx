require 'sinatra'

post '/eval' do
  code = params[:code]
  result = eval(code)
  result.to_s
end
