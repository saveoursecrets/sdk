sos account migrate export target/demo-export.zip
#$ include ../includes/signin.sh
#$ regex (?i)export unencrypted
y
#$ wait

sos account migrate export --force target/demo-export.zip
#$ include ../includes/signin.sh
#$ regex (?i)export unencrypted
y
#$ wait

sos account migrate import --format onepassword.csv $MIGRATE_1PASSWORD
#$ include ../includes/signin.sh
#$ regex (?i)imported
#$ wait

sos account migrate import --format dashlane.zip $MIGRATE_DASHLANE
#$ include ../includes/signin.sh
#$ regex (?i)imported
#$ wait

sos account migrate import --format bitwarden.csv $MIGRATE_BITWARDEN
#$ include ../includes/signin.sh
#$ regex (?i)imported
#$ wait

sos account migrate import --format firefox.csv $MIGRATE_FIREFOX
#$ include ../includes/signin.sh
#$ regex (?i)imported
#$ wait

sos account migrate import --format macos.csv $MIGRATE_MACOS
#$ include ../includes/signin.sh
#$ regex (?i)imported
#$ wait
