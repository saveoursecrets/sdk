# generate a CSV security report
sos security-report --force target/report.csv
#$ include ../includes/signin.sh
#$ regex (?i)generated
#$ wait

# or JSON if you prefer
sos security-report --format json --force target/report.json
#$ include ../includes/signin.sh
#$ regex (?i)generated
#$ wait

# to include entries that passed the threshold
sos security-report \
  --include-all \
  --format json \
  --force target/report.json
#$ include ../includes/signin.sh
#$ regex (?i)generated
#$ wait
