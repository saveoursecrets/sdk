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

account rename -a $ACCOUNT_NAME NewDemo
#$ wait

account rename -a NewDemo $ACCOUNT_NAME
#$ wait

#############################################################
# MIGRATE
#############################################################

account migrate export --force target/demo-export.zip
#$ regex (?i)export unencrypted
y
#$ wait

account migrate import --format onepassword.csv $MIGRATE_1PASSWORD
#$ regex (?i)imported
#$ wait

account migrate import --format dashlane.zip $MIGRATE_DASHLANE
#$ regex (?i)imported
#$ wait

account migrate import --format bitwarden.csv $MIGRATE_BITWARDEN
#$ regex (?i)imported
#$ wait

account migrate import --format firefox.csv $MIGRATE_FIREFOX
#$ regex (?i)imported
#$ wait

account migrate import --format macos.csv $MIGRATE_MACOS
#$ regex (?i)imported
#$ wait

#############################################################
# CONTACTS
#############################################################

account contacts export --force $CONTACTS_EXPORT
#$ regex (?i)contacts exported
#$ wait

account contacts import $ACCOUNT_CONTACTS
#$ regex (?i)contacts imported
#$ wait

#############################################################
# FOLDER
#############################################################

folder new $FOLDER_NAME
#$ regex (?i)created
#$ wait

folder ls -v
#$ wait

folder info -v
#$ wait

folder keys -f $FOLDER_NAME
#$ wait

folder commits -f $FOLDER_NAME
#$ wait

folder rename -f $FOLDER_NAME $NEW_FOLDER_NAME
#$ wait

folder rename -f $NEW_FOLDER_NAME $FOLDER_NAME
#$ wait

folder history compact -f $FOLDER_NAME
#$ regex (?i)remove history
y
#$ wait

folder history check -f $FOLDER_NAME
#$ wait

folder history list -f $FOLDER_NAME
#$ wait

folder remove -f $FOLDER_NAME
#$ regex (?i)delete folder
y
#$ regex (?i)folder deleted
#$ wait

#############################################################
# TEARDOWN
#############################################################

switch "$ACCOUNT_NAME_ALT"
#$ include ../includes/signin.sh
#$ wait

account delete
#$ include ../includes/signin.sh
#$ regex (?i)delete account
y
#$ regex (?i)account deleted
#$ wait
