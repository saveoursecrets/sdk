# set the hashcheck server URL
sos prefs string hashcheck.server https://hashcheck.saveoursecrets.com
#$ include ../includes/signin.sh
#$ regex (?i)set
#$ wait
