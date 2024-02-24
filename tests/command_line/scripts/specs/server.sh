sos server add $DEMO_SERVER
#$ include ../includes/signin.sh
#$ regex (?i)added
#$ wait

sos server ls
#$ include ../includes/signin.sh
#$ wait

sos server rm $DEMO_SERVER 
#$ include ../includes/signin.sh
#$ regex (?i)removed
#$ wait
