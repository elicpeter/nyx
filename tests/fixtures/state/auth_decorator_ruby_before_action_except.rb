# before_action :authenticate_user!, except: [:handle_index]
# Method `handle_index` is in `except`, so the filter is skipped and the
# unauthed privileged sink should fire.
class UsersController
  before_action :authenticate_user!, except: [:handle_index]

  def handle_index
    system("ls /tmp")
  end
end
