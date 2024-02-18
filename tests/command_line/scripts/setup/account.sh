sos account new Demo
#$ expect Choose a password
2
#$ regex (?i)password
$ACCOUNT_PASSWORD
#$ regex (?i)password
$ACCOUNT_PASSWORD
#$ regex create a new account
y
#$ wait
