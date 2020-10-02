#!/bin/sh

set -eux

BUNDLE=${BUNDLE:-bundle26}
RUBY=${RUBY:-ruby26}

${BUNDLE} install --path vendor/bundle
${RUBY} file_server.rb &
${RUBY} server.rb
