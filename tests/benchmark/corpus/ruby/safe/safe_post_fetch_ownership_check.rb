# Rails canonical "load by id, then check ownership" idiom: the row is
# fetched by user-controlled id, and a per-record permission predicate
# (`visible?`, `editable?`, `deletable?`, …) immediately after is the
# ownership gate. The check is textually AFTER the fetch, so the
# baseline `check.line <= op.line` rule cannot cover the row-fetch op
# directly; the row-fetch exemption (`row_population_data` reverse-walk
# in `auth_check_covers_subject`) closes the gap by recognising the row
# variable as the auth check's subject.
#
# Engine must NOT raise `rb.auth.missing_ownership_check` on any of
# these actions.
class IssuesController < ApplicationController
  before_action :authenticate_user!

  def show
    @issue = Issue.find(params[:id])
    raise Unauthorized unless @issue.visible?
    render :show
  end

  def edit
    @issue = Issue.find(params[:id])
    return render_403 unless @issue.editable?
  end

  def destroy
    @issue = Issue.find(params[:id])
    return render_403 unless @issue.deletable?
    @issue.destroy
  end

  def comment
    @issue = Issue.find(params[:id])
    raise Unauthorized unless @issue.commentable?
  end

  def via_owned_by
    @record = Record.find(params[:id])
    raise Unauthorized unless @record.owned_by?(current_user)
  end
end
