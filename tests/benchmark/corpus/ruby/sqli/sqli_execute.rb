def get_user(params)
  id = params[:id]
  connection.execute("SELECT * FROM users WHERE id = " + id)
end
