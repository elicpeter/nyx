# before_action :authenticate_user! applies to every method in the class —
# both handler methods should be treated as protected.
class UsersController
  before_action :authenticate_user!

  def handle_request
    system("ls /tmp")
  end

  def handle_admin_request
    system("service restart")
  end
end
