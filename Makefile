# AES-128-GCM AEAD FPGA core - build / lint / sim / synth
#
# Targets:
#   make lint            verilator --lint-only on RTL (sbox + round + key
#                        expand + core + ghash + aead)
#   make sim             build the AEAD top-level simulator
#   make test            build + run AEAD sim, check for "+PASS"
#   make sim-ghash       build the GHASH unit-test simulator
#   make test-ghash      build + run GHASH unit tests
#   make test-aead       alias for `test`
#   make test-all        run every test suite
#   make synth           Yosys: ice40 + ecp5 + xilinx generic for the AEAD top
#   make synth_report    run all available toolchains and emit SYNTH_REPORT.md
#   make vhdl-test       GHDL+Verilator co-sim of the VHDL wrapper (if installed)
#   make clean           remove build artifacts
#   make regen_vectors   regenerate tb/random_vectors.h from cryptography

VERILATOR ?= verilator
YOSYS     ?= yosys
GHDL      ?= ghdl
VIVADO    ?= vivado
QUARTUS   ?= quartus_sh

RTL_AES := \
    rtl/aes_sbox.sv \
    rtl/aes_inv_sbox.sv \
    rtl/aes_key_expand.sv \
    rtl/aes_round.sv \
    rtl/aes_core.sv

RTL_GHASH := \
    rtl/ghash_core.sv

RTL_AEAD := \
    $(RTL_AES) \
    $(RTL_GHASH) \
    rtl/aes_gcm_aead.sv

TB_AEAD_TOP := tb/aes_gcm_tb.sv
TB_AEAD_AUX := tb/aes_gcm_assertions.sv tb/aes_gcm_cov.sv
TB_AEAD_CPP := tb/sim_main.cpp

TB_GHASH_TOP := tb/ghash_tb.sv
TB_GHASH_CPP := tb/sim_main_ghash.cpp

VFLAGS := -Wall -Wno-UNUSEDPARAM -Wno-UNUSEDSIGNAL

.PHONY: lint sim test sim-ghash test-ghash test-aead test-all \
        synth synth_report vhdl-test clean regen_vectors

lint:
	$(VERILATOR) --lint-only $(VFLAGS) --top-module aes_gcm_tb \
	    $(RTL_AEAD) $(TB_AEAD_TOP) $(TB_AEAD_AUX)
	$(VERILATOR) --lint-only $(VFLAGS) --top-module ghash_tb \
	    $(RTL_GHASH) $(TB_GHASH_TOP)

sim: obj_dir/Vaes_gcm_tb

obj_dir/Vaes_gcm_tb: $(RTL_AEAD) $(TB_AEAD_TOP) $(TB_AEAD_AUX) $(TB_AEAD_CPP) \
                     tb/random_vectors.h
	$(VERILATOR) --cc --exe --build $(VFLAGS) --assert --public-flat-rw \
	    --top-module aes_gcm_tb \
	    $(RTL_AEAD) $(TB_AEAD_TOP) $(TB_AEAD_AUX) $(TB_AEAD_CPP) \
	    -o Vaes_gcm_tb

test: sim
	./obj_dir/Vaes_gcm_tb | tee test.log
	@grep -q "+PASS" test.log && echo "TESTS PASSED" || (echo "TESTS FAILED" && exit 1)

test-aead: test

sim-ghash: obj_dir_ghash/Vghash_tb

obj_dir_ghash/Vghash_tb: $(RTL_GHASH) $(TB_GHASH_TOP) $(TB_GHASH_CPP)
	$(VERILATOR) --cc --exe --build $(VFLAGS) --top-module ghash_tb \
	    --Mdir obj_dir_ghash \
	    $(RTL_GHASH) $(TB_GHASH_TOP) $(TB_GHASH_CPP) \
	    -o Vghash_tb

test-ghash: sim-ghash
	./obj_dir_ghash/Vghash_tb | tee test_ghash.log
	@grep -q "+PASS" test_ghash.log && echo "GHASH TESTS PASSED" || (echo "GHASH TESTS FAILED" && exit 1)

test-all: test-ghash test

# ---------- Open synthesis (Yosys) ------------------------------------------
synth:
	$(YOSYS) -p "read_verilog -sv $(RTL_AEAD); hierarchy -top aes_gcm_aead; synth_ice40 -top aes_gcm_aead; stat" \
	    | tee synth_ice40.log
	$(YOSYS) -p "read_verilog -sv $(RTL_AEAD); hierarchy -top aes_gcm_aead; synth_ecp5 -top aes_gcm_aead -abc9; stat" \
	    | tee synth_ecp5.log
	$(YOSYS) -p "read_verilog -sv $(RTL_AEAD); hierarchy -top aes_gcm_aead; synth_xilinx -top aes_gcm_aead; stat" \
	    | tee synth_xilinx.log

# ---------- Cross-toolchain synthesis report --------------------------------
synth_report:
	@bash scripts/synth_report.sh

# ---------- VHDL co-sim (optional) ------------------------------------------
vhdl-test:
	@which $(GHDL) >/dev/null 2>&1 || { echo "ghdl not installed - skipping vhdl-test"; exit 0; }
	@which $(VERILATOR) >/dev/null 2>&1 || { echo "verilator not installed"; exit 1; }
	@bash scripts/vhdl_cosim.sh

clean:
	rm -rf obj_dir obj_dir_ghash \
	    test.log test_ghash.log \
	    synth_ice40.log synth_ecp5.log synth_xilinx.log \
	    synth_report/ SYNTH_REPORT.md

regen_vectors:
	python3 tb/gen_random_vectors.py > tb/random_vectors.h
