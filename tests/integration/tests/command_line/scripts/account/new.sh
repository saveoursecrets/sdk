sos account new $ACCOUNT_NAME
#$ expect Choose a password
2
#$ regex (?i)password
$ACCOUNT_PASSWORD
#$ regex (?i)password
$ACCOUNT_PASSWORD
#$ regex create a new account
y
#$ wait
