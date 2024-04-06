
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	# echo "#define C_KEY \"ac22c839be8b62b7efe09d0270271042\"" > global_secrets.h
	python3 script.py
clean:
	rm -f global_secrets.h
