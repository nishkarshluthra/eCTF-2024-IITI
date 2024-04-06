build_ap:
	ectf_build_ap -d ./ -on ap --p 123456 -c 2 -ids "0x11111124, 0x11111125" -b "Test boot message" -t 0123456789abcdef -od build

build_comp1:
	ectf_build_comp -d ./ -on comp -od build -id 0x11111124 -b "Component boot 1" -al "McLean" -ad "01/01/24" -ac "Jha"

build_comp2:
	ectf_build_comp -d ./ -on comp2 -od build -id 0x11111125 -b "Component boot 2" -al "59e99f6ce91617a2999b4c3eb93777e057d86a7b82baca69eaf943723e640144" -ad "1357bec86dcaab7452d6ffcc3c260fdfbeb0bfabfc342759733211a298f8e5b0" -ac "1357bec86dcaab7452d6ffcc3c260fdfbeb0bfabfc342759733211a298f8e5b0"

build_comp3:
	ectf_build_comp -d ./ -on comp3 -od build -id 0x11111126 -b "Component boot 3" -al "Bedford" -ad "22/08/2023" -ac "1357bec86dcaab7452d6ffcc3c260fdfbeb0bfabfc342759733211a298f8e5b0"

update_ap:
	ectf_update --infile build/ap.img --port $(port)

update_comp1:
	ectf_update --infile build/comp.img --port $(port)

update_comp2:
	ectf_update --infile build/comp2.img --port $(port)

update_comp3:
	ectf_update --infile build/comp3.img --port $(port)

attest_comp1:
	ectf_attestation -a $(port) -p 123456 -c 0x11111124

attest_comp2:
	ectf_attestation -a $(port) -p 123456 -c 0x11111125

list:
	ectf_list -a $(port)

boot:
	ectf_boot -a $(port)

replace:
	ectf_replace -a $(port) -t 0123456789abcdef -i 0x11111126 -o 0x11111125