sos shell
#$ include ../includes/signin.sh
#$ wait

#############################################################
# BASIC
#############################################################

whoami
#$ wait
pwd
#$ wait
cd Archive
#$ wait
cd Documents
#$ wait

#############################################################
# SWITCH
#############################################################

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

#############################################################
# ACCOUNT
#############################################################

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

account migrate export --force target/demo-export.zip
#$ regex (?i)export unencrypted
y
#$ wait
