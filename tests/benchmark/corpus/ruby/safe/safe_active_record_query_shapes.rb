# Rails ActiveRecord query methods (where/order/group/having/joins/pluck) are
# SQLi sinks ONLY when arg 0 is a string with `#{...}` interpolation. The hash
# form (`where(id: x)`), symbol form (`order(:created_at)`), and parameterised
# string form (`where("a = ?", x)`) are intrinsically safe — Rails escapes the
# values. This fixture exercises every safe arg-0 shape.
#
# Engine must NOT raise SQL_QUERY-class findings (no taint-unsanitised-flow,
# no cfg-unguarded-sink) on any of these calls. Auth-style findings on the
# methods that read by user-controlled id are deliberately avoided here by
# preceding every action with `before_action :authenticate_user!` (the auth
# analysis recognises this as a class-level guard) and using non-id args.
class IssuesController < ApplicationController
  before_action :authenticate_user!

  def safe_listings
    Issue.where(deleted: false)
    Issue.where(:status => 'open')
    Issue.where("active = ?", true)
    Issue.where("name = :name", name: 'foo')
    Project.order(:created_at)
    Issue.pluck(:id, :title)
    Project.group(:status)
    Issue.joins(:project, :assigned_to)
    Issue.group(:project_id).having("count(*) > 1")
    Issue.where(deleted: false).preload(:project, :status).to_a
    Issue.where(deleted: false).order(:created_at).pluck(:id, :title)
  end
end
