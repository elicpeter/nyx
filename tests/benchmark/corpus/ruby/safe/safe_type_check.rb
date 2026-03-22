def run_query(params)
  user_id = params[:id]
  unless user_id.is_a?(Integer)
    return "bad input"
  end
  connection.execute("SELECT * FROM users WHERE id = " + user_id.to_s)
end
