# disable some menu shortcut types
sos prefs string-list menu.shortcutTypeItems certificate card
#$ include ../includes/signin.sh
#$ regex (?i)set
#$ wait
