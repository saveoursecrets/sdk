sos account migrate export target/demo/export.zip
#$ include ../../includes/signin.sh
#$ regex (?i)export unencrypted
y
#$ wait

sos account migrate export --force target/demo/export.zip
#$ include ../../includes/signin.sh
#$ regex (?i)export unencrypted
y
#$ wait
