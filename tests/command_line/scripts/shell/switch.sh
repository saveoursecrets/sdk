account new "$ACCOUNT_NAME_ALT"
#$ expect Choose a password
2
#$ regex (?i)password
$ACCOUNT_PASSWORD
#$ regex (?i)password
$ACCOUNT_PASSWORD
#$ regex create a new account
y
#$ wait

switch "$ACCOUNT_NAME_ALT"
#$ include ../includes/signin.sh
#$ wait

switch "$ACCOUNT_NAME"
#$ include ../includes/signin.sh
#$ wait
