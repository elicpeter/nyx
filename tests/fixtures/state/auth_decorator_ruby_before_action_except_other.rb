# before_action :authenticate_user!, except: [:handle_index]
# Method `handle_create` is NOT in `except`, so the filter applies and the
# sink should NOT fire.
class UsersController
  before_action :authenticate_user!, except: [:handle_index]

  def handle_create
    system("service restart")
  end
end
