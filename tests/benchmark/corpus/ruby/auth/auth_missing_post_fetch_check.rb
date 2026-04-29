# Counterpart to `safe_post_fetch_ownership_check.rb`: same controller
# shape, but the action *omits* the per-record permission check. The
# row is loaded by user-controlled id and used directly without any
# ownership gate. Engine must keep flagging this as
# `rb.auth.missing_ownership_check` even though the safe-shape fixtures
# train the row-fetch exemption on the same `Issue.find(params[:id])`
# pattern.
class IssuesController < ApplicationController
  before_action :authenticate_user!

  def reveal
    @issue = Issue.find(params[:id])
    render :show
  end
end
