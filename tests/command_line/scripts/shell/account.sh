account ls -v
#$ wait

account backup --force $ACCOUNT_BACKUP
#$ regex (?i)archive created
#$ wait

account restore $ACCOUNT_BACKUP
#$ regex Overwrite all account
y
#$ include ../includes/signin.sh
#$ wait

account info -v
#$ wait

account stats
#$ wait

account stats --json
#$ wait

account rename -a $ACCOUNT_NAME NewDemo
#$ wait

account rename -a NewDemo $ACCOUNT_NAME
#$ wait

