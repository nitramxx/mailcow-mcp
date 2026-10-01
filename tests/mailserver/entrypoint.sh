#!/bin/sh
set -e
dovecot
exec postfix start-fg
