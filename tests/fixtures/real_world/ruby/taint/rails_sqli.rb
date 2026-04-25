class PostsController < ApplicationController
  def search
    query = params[:q]
    @posts = Post.find_by_sql("SELECT * FROM posts WHERE title LIKE '%#{query}%'")
  end

  def safe_search
    query = params[:q]
    @posts = Post.where("title LIKE ?", "%#{query}%")
  end
end
