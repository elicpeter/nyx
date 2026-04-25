require 'sinatra'

def build_query(filter)
  "SELECT * FROM logs WHERE msg LIKE '%#{filter}%'"
end

get '/search' do
  filter = params['filter']
  query = build_query(filter)
  db = ActiveRecord::Base.connection
  db.select_all(query)
end
