# list accounts
account ls -v
#$ wait

# backup current account
account backup --force $ACCOUNT_BACKUP
#$ regex (?i)archive created
#$ wait

# account information
account info -v
#$ wait

# account statistics
account stats
#$ wait

account stats --json
#$ wait

# rename the account
account rename -a $ACCOUNT_NAME NewDemo
#$ wait

account rename -a NewDemo $ACCOUNT_NAME
#$ wait
