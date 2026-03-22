class SearchController < ApplicationController
  def search
    query = params[:q]
    results = ActiveRecord::Base.connection.execute(
      "SELECT * FROM articles WHERE title LIKE '%" + query + "%'"
    )
    render json: results
  end
end
