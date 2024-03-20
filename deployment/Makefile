
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	echo "#define SECRET 1234" > global_secrets.h
	echo '#define C_KEY "8d40b17a2953df92b3196ed62a5c01ea"' > global_secrets.h
clean:
	rm -f global_secrets.h
