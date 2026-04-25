def get_user(params)
  id = params[:id]
  User.find_by_sql("SELECT * FROM users WHERE id = " + id)
end
