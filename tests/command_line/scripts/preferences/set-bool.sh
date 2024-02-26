# disable hashcheck service
sos prefs bool hashcheck.enabled false
#$ include ../includes/signin.sh
#$ regex (?i)set
#$ wait
