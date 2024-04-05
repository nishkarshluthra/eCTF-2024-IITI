build_ap:
	ectf_build_ap -d ../ectf-2024-IITI/ -on ap --p 123456 -c 2 -ids "0x11111124, 0x11111125" -b "Test boot message" -t 0123456789abcdef -od build

build_comp1:
	ectf_build_comp -d ../eCTF-2024-IITI/ -on comp -od build -id 0x11111124 -b "Component boot 1" -al "McLean" -ad "01/01/24" -ac "Jha"

build_comp2:
	ectf_build_comp -d ../eCTF-2024-IITI/ -on comp2 -od build -id 0x11111125 -b "Component boot 2" -al "123456789987654321" -ad "02/02/24" -ac "This String has more than 16 characters"

update_ap:
	ectf_update --infile build/ap.img --port $(port)

update_comp1:
	ectf_update --infile build/comp.img --port $(port)

update_comp2:
	ectf_update --infile build/comp2.img --port $(port)

attest_comp1:
	ectf_attestation -a $(port) -p 123456 -c 0x11111124

attest_comp2:
	ectf_attestation -a $(port) -p 123456 -c 0x11111125

list:
	ectf_list -a $(port)

boot:
	ectf_boot -a $(port)