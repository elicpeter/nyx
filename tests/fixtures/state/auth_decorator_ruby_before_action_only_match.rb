# before_action :authenticate_user!, only: [:handle_create]
# Method `handle_create` matches the only-list, so the auth filter applies
# and the sink should NOT fire.
class UsersController
  before_action :authenticate_user!, only: [:handle_create]

  def handle_create
    system("service restart")
  end
end
