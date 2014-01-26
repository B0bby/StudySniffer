# Is there a better way to do this? I dunno.
#   This is called by a cron job every fifteen minutes.

import subprocess

subprocess.Popen(["git", "fetch", "--all"])
subprocess.Popen(["git", "reset", "--hard", "origin/master"])
