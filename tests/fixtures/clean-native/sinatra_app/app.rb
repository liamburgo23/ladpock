require "sinatra"

before do
  halt 401 unless session[:user_id]
end

delete "/comments/:id" do
  Comment.where(id: params[:id], user_id: session[:user_id]).destroy_all
end
