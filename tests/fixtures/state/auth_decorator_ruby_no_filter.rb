# No before_action — finding should fire.
class UsersController
  def handle_request
    system("ls /tmp")
  end
end
