# Is there a better way to do this? I dunno.
#   This is called by a cron job every fifteen minutes.

import subprocess

subprocess.check_output(["git", "fetch", "--all"])
subprocess.check_output(["git", "reset", "--hard", "origin/master"])
