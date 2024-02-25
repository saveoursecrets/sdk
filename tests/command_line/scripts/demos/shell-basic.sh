sos shell
#$ include ../includes/signin.sh
#$ wait

#$ include ../shell/basic.sh
#$ include ../shell/account.sh

# import passwords from a Safari/MacOS CSV file
account migrate import --name "MacOS Passwords" --format macos.csv $MIGRATE_MACOS
#$ regex (?i)imported
#$ wait

# export unencrypted secrets to migrate to another app
account migrate export --force target/demo-export.zip
#$ regex (?i)export unencrypted
y
#$ wait

#$ include ../shell/contacts.sh
#$ include ../shell/folder.sh
#$ include ../shell/secret.sh
