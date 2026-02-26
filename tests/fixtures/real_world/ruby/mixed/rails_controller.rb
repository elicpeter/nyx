class UsersController
  def show
    user_id = params[:id]
    query = "SELECT * FROM users WHERE id = #{user_id}"
    @user = execute_query(query)
  end

  def exec_cmd
    cmd = params[:cmd]
    system(cmd)
  end

  def safe_show
    user_id = params[:id]
    @user = User.find(user_id)
  end
end
