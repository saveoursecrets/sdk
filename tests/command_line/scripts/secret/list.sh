sos secret ls
#$ include ../includes/signin.sh
#$ wait

sos secret ls --verbose
#$ include ../includes/signin.sh
#$ wait

sos secret ls --all
#$ include ../includes/signin.sh
#$ wait

sos secret ls --favorites
#$ include ../includes/signin.sh
#$ wait
