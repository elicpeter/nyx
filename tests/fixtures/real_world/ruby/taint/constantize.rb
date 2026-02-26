require 'sinatra'

get '/create' do
  class_name = params[:type]
  klass = class_name.constantize
  instance = klass.new
  instance.to_s
end
