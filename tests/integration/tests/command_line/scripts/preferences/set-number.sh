# set the autolock timeout minutes
sos prefs number autolock.timeout 30
#$ include ../includes/signin.sh
#$ regex (?i)set
#$ wait
