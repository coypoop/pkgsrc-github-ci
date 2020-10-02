require 'bundler/setup'
require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements
require 'git'

set :port, 3000
set :bind, '0.0.0.0'


# This is template code to create a GitHub App server.
# You can read more about GitHub Apps here: # https://developer.github.com/apps/
#
# On its own, this app does absolutely nothing, except that it can be installed.
# It's up to you to add functionality!
# You can check out one example in advanced_server.rb.
#
# This code is a Sinatra app, for two reasons:
#   1. Because the app will require a landing page for installation.
#   2. To easily handle webhook events.
#
# Of course, not all apps need to receive and process events!
# Feel free to rip out the event handling code if you don't need it.
#
# Have fun!
#

class GHAapp < Sinatra::Application

  # Expects that the private key in PEM format. Converts the newlines
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end

  get '/logs/' do
      File.read(File.join('public', 'index.html'))
  end

  # Before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature
  end


  post '/event_handler' do

  case request.env['HTTP_X_GITHUB_EVENT']
  when 'check_run'
    sha = @payload['check_run'].nil? ? @payload['check_suite']['head_sha'] : @payload['check_run']['head_sha']

    # Check that the event is being sent to this app
    if @payload['check_run']['app']['id'].to_s === APP_IDENTIFIER
      case @payload['action']
      when 'created'
        initiate_check_run
      when 'rerequested'
        create_check_run
      end
    end

  when 'check_suite'
    # A new check_suite has been created. Create a new check run with status queued
    if @payload['action'] == 'requested' || @payload['action'] == 'rerequested'
      create_check_run
    end
  end
    # # # # # # # # # # # #
    # ADD YOUR CODE HERE  #
    # # # # # # # # # # # #

    200 # success status
  end


  helpers do


    # Clones the repository to the current working directory, updates the
    # contents using Git pull, and checks out the ref.
    #
    # full_repo_name  - The owner and repo. Ex: octocat/hello-world
    # repository      - The repository name
    # default_branch  - The default branch name
    # ref             - The branch, commit SHA, or tag to check out
    def clone_repository(full_repo_name, repository, default_branch, ref)
      @git = Git.clone("https://x-access-token:#{@installation_token.to_s}@github.com/#{full_repo_name}.git", repository, :branch => default_branch)
      pwd = Dir.getwd()
      Dir.chdir(repository)
      @git.checkout(ref)
      Dir.chdir(pwd)
      @git
    end

    # Create a new check run with the status queued
    def create_check_run
      authenticate_app
      # Authenticate the app installation in order to run API operations
      authenticate_installation(@payload)

      # # At the time of writing, Octokit does not support the Checks API yet, but
      # it does provide generic HTTP methods you can use:
      # https://developer.github.com/v3/checks/runs/#create-a-check-run
      check_run = @installation_client.post(
        "repos/#{@payload['repository']['full_name']}/check-runs",
        {
          # This header allows for beta access to Checks API
          accept: 'application/vnd.github.antiope-preview+json',
          # The name of your check run.
          name: report_operating_system(),
          # The payload structure differs depending on whether a check run or a check suite event occurred.
          head_sha: @payload['check_run'].nil? ? @payload['check_suite']['head_sha'] : @payload['check_run']['head_sha']
        }
      )
    end

    # Start the CI process
    def initiate_check_run
      run_conclusion = "failure"
      begin
        full_repo_name = @payload['repository']['full_name']
        repository     = @payload['repository']['name']
        default_branch = @payload['repository']['default_branch']
        head_sha       = @payload['check_run']['head_sha']

        workdir = ENV['HOME'] + "/build-output/" + head_sha
        logdir = __dir__ + "/public/#{head_sha}"
        worklog = "#{logdir}/output.log"
        `rm -rf #{workdir} #{logdir}`
        `mkdir -p #{workdir} #{logdir}`
        `touch #{worklog}`
        Dir.chdir(workdir)

        puts "cloning at SHA1 " + head_sha
        git = clone_repository(full_repo_name, repository, default_branch, head_sha)
        diff = @git.diff("#{head_sha}^", head_sha)

        diff_out = File.new("#{workdir}/diff.out", "w")
        diff_out.puts(diff)
        diff_out.close

        puts "creating mk.conf.frag"
        mk_conf_frag = File.new("#{workdir}/mk.conf.frag", "w")
        mk_conf_frag.puts("SKIP_LICENSE_CHECK=yes")
        mk_conf_frag.close
        
        puts "bootstrapping pbulk.sh, output at #{worklog}"
        `env PKGSRCDIR=#{workdir}/pkgsrc \
             PBULKPREFIX=#{workdir}/pbulk \
             PREFIX=#{workdir}/pkg \
             PACKAGES=#{workdir}/packages \
             BULKLOG=#{logdir}/ \
             TMPDIR=#{workdir} \
          sh #{workdir}/pkgsrc/mk/pbulk/pbulk.sh -l -u -c mk.conf.frag 2>&1 |tee #{worklog}`

        puts "creating pbulk.list for diff " + String(diff)
        pbulk_list = File.new("#{workdir}/pbulk/etc/pbulk.list", "w")
        pbulk_list.puts(generate_limited_list(diff))
        pbulk_list.close

        puts "running bulkbuild, output at #{worklog}"
        `#{workdir}/pbulk/bin/bulkbuild 2>&1 |tee #{worklog}`

        puts "inspecting errors..."
        error_size = File.size("#{logdir}/meta/error")
        if error_size > 0
          puts "some packages failed, marking as failure"
          run_conclusion = "failure"
          `echo "List of failed packages:"; cat #{logdir}/meta/error |tee #{worklog}`
        else
          puts "no failures, success"
          run_conclusion = "success"
        end
      ensure
        `rm -rf #{workdir}`

        authenticate_app
        # Authenticate the app installation in order to run API operations
        authenticate_installation(@payload)

        hostname=`hostname`.chomp

        # Mark the check run as complete!
        updated_check_run = @installation_client.patch(
          "repos/#{@payload['repository']['full_name']}/check-runs/#{@payload['check_run']['id']}",
          {
            # This header is necessary for beta access to Checks API
            accept: 'application/vnd.github.antiope-preview+json',
            name: report_operating_system(),
            status: 'completed',
            output: {
              title: 'build report',
              text: report_failures(logdir),
              summary: "http://#{hostname}:8000/#{head_sha}/meta/report.html",
            },
            conclusion: run_conclusion,
            completed_at: Time.now.utc.iso8601
          }
        )
      end
    end

    # Outputs a description for the running platform
    def report_operating_system()
      os_name=`uname`.chomp
      os_version=`uname -r`.chomp
      os_arch=`uname -m`.chomp

      if os_name.eql?("Linux")
          if File.exists?("/etc/os-release")
                os_name=`source /etc/os-release && echo $NAME`.chomp
                    os_version=`source /etc/os-release && echo $VERSION_ID`.chomp
                      end
      end

      if os_name.eql?("NetBSD")
          os_arch=`uname -p`.chomp
      end

      "#{os_name} #{os_version}/#{os_arch}"
    end

    # Outputs a string containing a Markdown-formatted report of failures
    #
    # logdir - directory containing BULKLOG (directory that contains meta/error)
    def report_failures(logdir)
      def report_failure(failed_package, logdir)
        reverse_stages = ["install.log", "build.log", "configure.log", "checksum.log", "depends.log", "pre-clean.log"]

        logs_filenames = Hash.new

        last_stage = ""
        reverse_stages.each do |stage_log|
          if(File.exists?("#{logdir}/#{failed_package}/#{stage_log}"))
            last_stage = stage_log
            break
          end
        end

        log_content = IO.readlines("#{logdir}/#{failed_package}/#{last_stage}").last(100).join('')

        %{
<details open=""><summary>#{failed_package} #{last_stage}</summary>
<p>

```
#{log_content}
```

</p>
</details>
        }
      end

      failure_report = ""
      File.readlines("#{logdir}/meta/error").each do |failed_package|
        failure_report = failure_report + report_failure(failed_package.chomp, logdir)
      end

      failure_report
    end

    # returns a string of packages were changed on a diff
    # in a format suitable to use as a limited_list file
    def generate_limited_list(diff)
      def is_pkg_change?(pkgdir)
        if pkgdir.start_with?("mk/")
          return false
        end

        if pkgdir.start_with?("doc/")
          return false
        end

        if pkgdir.split("/").length < 3
          return false
        end

        return true
      end

      # omit Makefile, patches/patch-aa... component
      def canonicalize_pkgdir(pkgdir)
        return pkgdir[/^[^\/]+\/[^\/]+/]
      end

      diff_paths = diff.map{ |diff| diff.path }

      pkgs = Array[]

      diff_paths.each do |diff_path|
        if is_pkg_change?(diff_path)
          pkgs.push(canonicalize_pkgdir(diff_path))
        end
      end

      return pkgs.nil? ? nil : pkgs.uniq.join("\n")
    end


    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail  'Invalid JSON (#{e}): #{@payload_raw}'
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app an not altererd by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minutes maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.
    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature` looks something
    # like this: 'sha1=123456'.
    # See https://developer.github.com/webhooks/securing/ for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

  end

  # Finally some logic to let us run this server directly from the command line,
  # or with Rack. Don't worry too much about this code. But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same—that is, we are running this file directly, call the
  # Sinatra run method
  run! if __FILE__ == $0
end
