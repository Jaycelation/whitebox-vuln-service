class UsersController < ApplicationController
  def show
    User.find_by_sql("SELECT * FROM users WHERE name = '#{params[:name]}'")  # EXPECT sql-injection direct
  end

  def ping
    Network.run_ping(params[:host])  # EXPECT command-injection cross-file
  end

  def count
    User.find_by_sql("SELECT * FROM users LIMIT #{params[:n].to_i}")
  end

  def go
    redirect_to params[:next]  # EXPECT open-redirect direct
  end
end
