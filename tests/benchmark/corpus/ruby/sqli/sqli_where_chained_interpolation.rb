# Real-world chained shape: `Model.where("...#{x}...").preload(...).to_a`.
# The CFG collapses chained calls into one node whose outermost callee is
# `to_a` (no args). The shape suppressor has to walk the receiver chain to
# reach the inner `where(...)` and detect the interpolation. Engine must
# still flag this — chain-walking only suppresses SAFE shapes.
class UsersController < ApplicationController
  def search
    name = params[:name]
    @users = User.where("name = '#{name}'").preload(:roles).to_a
  end
end
