=begin
-------------------------------------------------------------------------------------
--  SOURCE FILE:    site.rb -   Redirect web server for POC Arp Poisoning and DNS
--                              spoofing application.
--
--  PROGRAM:        site not meant to be directly executable
--                  ruby site.rb
--
--  FUNCTIONS:      Web server using ruby gem Sinatra
--
--  Ruby Gems required:     sinatra
--                          https://rubygems.org/gems/sinatra
--                      
--  DATE:           May/June 2014
--
--  REVISIONS:      See development repo: https://github.com/deuterium/comp8505-assign3
--
--  DESIGNERS:      Chris Wood - chriswood.ca@gmail.com
--
--  PROGRAMMERS:    Chris Wood - chriswood.ca@gmail.com
--  
--  NOTES:          none atm
---------------------------------------------------------------------------------------
=end
require 'sinatra'

# set port 80 and listen on all devices
set :port, 80
set :bind, '0.0.0.0'

#catch all landing page
get '/' do
  "probably not what you were looking for...."
end 
