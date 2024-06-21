# add a server this account will sync to
sos server add $DEMO_SERVER
#$ include ../includes/signin.sh
#$ regex (?i)added

# list servers
sos server ls
#$ include ../includes/signin.sh
#$ wait

# remove a server
sos server rm $DEMO_SERVER 
#$ include ../includes/signin.sh
#$ regex (?i)removed
#$ wait
