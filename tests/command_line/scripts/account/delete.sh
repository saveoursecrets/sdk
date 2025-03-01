sos account delete -a $ACCOUNT_NAME
#$ include ../includes/signin.sh
#$ regex (?i)delete account
y
#$ regex (?i)account deleted
#$ wait
