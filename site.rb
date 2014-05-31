require 'sinatra'

set :port, 80

get '/:var' do
  "Hello World: #{params[:var]}"
end 