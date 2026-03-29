module Admin
  class UsersController < ApplicationController
    before_action :require_login

    def update
      AdminRoleService.update!(params[:id], params[:role])
    end
  end
end
