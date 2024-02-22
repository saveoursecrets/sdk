sos secret add login --name "$LOGIN_NAME"
#$ include ../includes/signin.sh
#$ expect Username:
$LOGIN_SERVICE_NAME
#$ expect Website:
$LOGIN_URL
#$ expect Password:
$LOGIN_PASSWORD
#$ regex (?i)created
#$ wait
