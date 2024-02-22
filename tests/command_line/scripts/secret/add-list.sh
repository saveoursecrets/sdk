sos secret add list --name "$LIST_NAME"
#$ include ../includes/signin.sh
#$ expect Key:
$LIST_KEY_1
#$ expect Value:
$LIST_VALUE_1
#$ expect Add more
y
#$ expect Key:
$LIST_KEY_2
#$ expect Value:
$LIST_VALUE_2
#$ expect Add more
n
#$ regex (?i)created
#$ wait
