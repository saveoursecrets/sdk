sos account rename -a $ACCOUNT_NAME NewDemo
#$ include ../includes/signin.sh
#$ wait

sos account rename -a NewDemo $ACCOUNT_NAME
#$ include ../includes/signin.sh
#$ wait
