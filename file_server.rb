require 'webrick'

# Too hard to figure out how to use the other web server to do this.
# We need to serve files in subdirectories and having .log files count
# as text is a plus.

mime_types = WEBrick::HTTPUtils::DefaultMimeTypes
mime_types.store 'log', 'text/plain'

s = WEBrick::HTTPServer.new(
  :Port         => 8000,
  :DocumentRoot => "#{Dir.pwd}/public/", 
  :MimeTypes    => mime_types
)
trap('INT') { s.shutdown }
s.start
