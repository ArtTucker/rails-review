class ArticlesController < ApplicationController
  before_action :authenticate_user!
  before_action :find_article, only: [:show, :edit, :update, :destroy]

  # Show form to create article
  def new
    @article = Article.new
  end

  # Create article
  def create
    @article = Article.new(article_params)

    if @article.save
      redirect_to @article
    else
      render :new
    end
  end

  # Show specific article
  def show
  end

  # List all the articles
  def index
    @user = User.find(params[:user_id])
    @articles = @user.articles
  end

  # Find specific article to edit
  def edit
  end

  # Update article
  def update
    if @article.update_attributes(article_params)
      redirect_to @article
    else
      render :edit
    end
  end

  # Delete article
  def destroy
    @article.destroy
    redirect_to articles_path
  end

  private
  def article_params
    params.require(:article).permit(:title, :body)
  end

  def find_article
    @article = Article.find(params[:id])
  end
end
