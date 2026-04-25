# before_action :authenticate_user!, only: [:handle_create]
# Method `handle_index` is NOT in the only-list, so the filter does not apply
# — unauthed privileged sink should fire.
class UsersController
  before_action :authenticate_user!, only: [:handle_create]

  def handle_index
    system("ls /tmp")
  end
end
