require "sinatra"

post "/comments" do
  Comment.create(body: params[:body])
end

delete "/comments/:id" do
  halt 401 unless session[:user_id]
  Comment.find(params[:id]).destroy
end
