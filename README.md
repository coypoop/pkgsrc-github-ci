pkgsrc CI bot.

## Install

1. Register a GitHub app
- The permissions you need are "Read access to code and metadata" and "Read and write access to checks".
- Use the credentials to fill out an .env file as in [this guide](https://developer.github.com/apps/quickstart-guides/setting-up-your-development-environment/)

2. This script runs two web servers:
- Actual web hook at http://YOUR-IP:3000
- File serve at http://YOUR-IP:8000

3. Install Ruby, ruby bundler

4. Run the shell script start.sh

