# list accounts
account ls -v
#$ wait

# backup current account
account backup --force $ACCOUNT_BACKUP
#$ regex (?i)archive created
#$ wait

# restore from backup archive
account restore $ACCOUNT_BACKUP
#$ regex Overwrite all account
y
#$ include ../includes/signin.sh
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

