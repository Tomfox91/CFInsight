.SUFFIXES:
.SECONDARY:
.DELETE_ON_ERROR:
.PHONY: nginx-tests decache printenv spec spec-baseline spec-cfi spec-scrub


all:
	@echo "Please request a target"

# variables
export CBCH_VALGRIND=<<<<<VALGRIND_PATH>>>>>
export CBCH_NGINX=<<<<<NGINX_PATH>>>>>
export CBCH_RESROOT=$(shell pwd)/results/
CBCH_SPEC:=<<<<<SPEC_PATH>>>>>

printenv:
	printenv


nginx-tests:
	rm -rf results/nginx/cfggrind results/nginx/binaries
	cd /home/tf/ncfi/test-nginx; TEST_NGINX_BINARY=/home/tf/nfs/cfggrind/multirun/nginx-tests TEST_NGINX_UNSAFE=1 prove .
	./copy_binaries.sh results/nginx/cfggrind/tests-00000/map.map results/nginx/binaries


spec: spec-baseline spec-cfi

spec-scrub:
	./runcpu.sh --config clang11cfi.cfg --action=scrub tfset

spec-baseline:
	./runcpu.sh --config clang11baseline.cfg --action=setup --size test,train,ref --tuning base tfset

spec-cfi: spec-cfi-600.perlbench_s spec-cfi-602.gcc_s spec-cfi-605.mcf_s spec-cfi-619.lbm_s spec-cfi-620.omnetpp_s spec-cfi-623.xalancbmk_s spec-cfi-625.x264_s spec-cfi-631.deepsjeng_s spec-cfi-638.imagick_s spec-cfi-641.leela_s spec-cfi-644.nab_s spec-cfi-657.xz_s
	@true

spec-cfi-%:
	export LLVM_TYPEDUMP_OUTDIR="$(CURDIR)/results/$*/functioncalls" && \
	mkdir -p "$$LLVM_TYPEDUMP_OUTDIR" && \
	rm -f "$$LLVM_TYPEDUMP_OUTDIR"/* && \
	./runcpu.sh --config clang11cfi.cfg --action=setup --size test,train,ref --tuning base --rebuild $*

grindspec-test-%:
	rm -rf results/$*/cfggrind/test_*
	python3 -B -m multirun.run_spec $(CBCH_SPEC)/benchspec/CPU/$*/run/run_base_test_cl11cfi-m64.0000/

grindspec-train-%:
	rm -rf results/$*/cfggrind/train_*
	python3 -B -m multirun.run_spec $(CBCH_SPEC)/benchspec/CPU/$*/run/run_base_train_cl11cfi-m64.0000/

grindspec-refspeed-%:
	rm -rf results/$*/cfggrind/refspeed_*
	python3 -B -m multirun.run_spec $(CBCH_SPEC)/benchspec/CPU/$*/run/run_base_refspeed_cl11cfi-m64.0000/
	./copy_binaries.sh results/$*/cfggrind/refspeed_cl11cfi!00000/map.map results/$*/binaries





results/%/map.json: results/%/cfggrind/*/map.map multiparse/mapp.py
	pypy3 -B -m multiparse.mapp \
	  results/$*/cfggrind/ results/$*/binaries/ $@


results/%/angr-cfg-fast.json: \
	results/%/map.json results/%/binaries/ \
	angrmgmt/static_cfg_generator.py
	
	pypy3 -B -m angrmgmt.static_cfg_generator \
	  results/$*/map.json results/$*/binaries/ $@ \
	  --all_libs --fast --without_simpro

results/%/angr-cfg-emulated.json: \
	results/%/map.json results/%/binaries/ \
	angrmgmt/static_cfg_generator.py
	
	pypy3 -B -m angrmgmt.static_cfg_generator \
	  results/$*/map.json results/$*/binaries/ $@ \
	  --only_main --emulated --with_simpro


results/623.xalancbmk_s/merged-cfg.json: \
	results/623.xalancbmk_s/angr-cfg-fast.json \
	results/623.xalancbmk_s/map.json results/623.xalancbmk_s/binaries/ \
	multiparse/*.py angrmgmt/instr_analyzer.py
	
	pypy3 -B -m multiparse.multiparse \
	  results/623.xalancbmk_s/angr-cfg-fast.json \
	  results/623.xalancbmk_s/map.json results/623.xalancbmk_s/binaries/ $@

results/644.nab_s/merged-cfg.json: \
	results/644.nab_s/angr-cfg-fast.json \
	results/644.nab_s/map.json results/644.nab_s/binaries/ \
	multiparse/*.py angrmgmt/instr_analyzer.py
	
	pypy3 -B -m multiparse.multiparse \
	  results/644.nab_s/angr-cfg-fast.json \
	  results/644.nab_s/map.json results/644.nab_s/binaries/ $@

results/600.perlbench_s/merged-cfg.json: \
	results/600.perlbench_s/angr-cfg-fast.json \
	results/600.perlbench_s/map.json results/600.perlbench_s/binaries/ \
	multiparse/*.py angrmgmt/instr_analyzer.py
	
	pypy3 -B -m multiparse.multiparse \
	  results/600.perlbench_s/angr-cfg-fast.json \
	  results/600.perlbench_s/map.json results/600.perlbench_s/binaries/ $@

results/638.imagick_s/merged-cfg.json: \
	results/638.imagick_s/angr-cfg-fast.json \
	results/638.imagick_s/map.json results/638.imagick_s/binaries/ \
	multiparse/*.py angrmgmt/instr_analyzer.py
	
	pypy3 -B -m multiparse.multiparse \
	  results/638.imagick_s/angr-cfg-fast.json \
	  results/638.imagick_s/map.json results/638.imagick_s/binaries/ $@

results/602.gcc_s/merged-cfg.json: \
	results/602.gcc_s/angr-cfg-fast.json \
	results/602.gcc_s/map.json results/602.gcc_s/binaries/ \
	multiparse/*.py angrmgmt/instr_analyzer.py
	
	pypy3 -B -m multiparse.multiparse \
	  results/602.gcc_s/angr-cfg-fast.json \
	  results/602.gcc_s/map.json results/602.gcc_s/binaries/ $@
	# unless it ends fine

results/%/merged-cfg.json: \
	results/%/angr-cfg-fast.json results/%/angr-cfg-emulated.json \
	results/%/map.json results/%/binaries/ \
	multiparse/*.py angrmgmt/instr_analyzer.py
	
	pypy3 -B -m multiparse.multiparse \
	  results/$*/angr-cfg-fast.json results/$*/angr-cfg-emulated.json \
	  results/$*/map.json results/$*/binaries/ $@


results/%/dwarf-fntypes.json: \
	results/%/map.json results/%/binaries/ fntypes/extract_dwarf_types.py
	
	pypy3 -B -m fntypes.extract_dwarf_types \
	  results/$*/map.json results/$*/binaries/ $@




results/%/oagraph/baseline.csv results/%/oagraph/base.json &: \
	results/%/merged-cfg.json oagraph_gen/*.py

	mkdir -p results/$*/oagraph
	python3 -B -m oagraph_gen.overappr_graph results/$*/merged-cfg.json \
	  --nofork \
	  --basegraph results/$*/oagraph/base.json \
	  --baseline results/$*/oagraph/baseline.csv

\
	results/%/oagraph/num_bd_cfi.csv \
	results/%/oagraph/num_id_cfi.csv \
	&: \
	results/%/merged-cfg.json results/%/dwarf-fntypes.json \
	results/%/functioncalls results/%/map.json \
	oagraph_gen/*.py

	mkdir -p results/$*/oagraph
	python3 -B -m oagraph_gen.overappr_graph results/$*/merged-cfg.json \
	  --num_bd_cfi results/$*/oagraph/num_bd_cfi.csv \
	  --num_id_cfi results/$*/oagraph/num_id_cfi.csv \


\
	results/%/oagraph/type_cfi.csv \
	results/%/oagraph/num_bd_type_cfi.csv \
	results/%/oagraph/num_id_type_cfi.csv \
	&: \
	results/%/merged-cfg.json results/%/dwarf-fntypes.json \
	results/%/functioncalls results/%/map.json \
	oagraph_gen/*.py

	mkdir -p results/$*/oagraph
	python3 -B -m oagraph_gen.overappr_graph results/$*/merged-cfg.json \
	  --dwarf_types_file results/$*/dwarf-fntypes.json \
	  --bin_dir results/$*/binaries/ \
	  --fn_calls results/$*/functioncalls --map_file results/$*/map.json \
	  --type_cfi results/$*/oagraph/type_cfi.csv \
	  --num_bd_type_cfi results/$*/oagraph/num_bd_type_cfi.csv \
	  --num_id_type_cfi results/$*/oagraph/num_id_type_cfi.csv


results/%/oagraph/numarg_cfi.csv: \
	results/%/merged-cfg.json results/%/dwarf-fntypes.json \
	results/%/functioncalls results/%/map.json \
	oagraph_gen/*.py

	mkdir -p results/$*/oagraph
	python3 -B -m oagraph_gen.overappr_graph results/$*/merged-cfg.json \
	  --nofork \
	  --numarg_cfi results/$*/oagraph/numarg_cfi.csv \
	  --dwarf_types_file results/$*/dwarf-fntypes.json \
	  --bin_dir results/$*/binaries/ \
	  --fn_calls results/$*/functioncalls --map_file results/$*/map.json

results/%/oagraph/sof_cfi.csv &: \
	results/%/merged-cfg.json oagraph_gen/*.py

	mkdir -p results/$*/oagraph
	python3 -B -m oagraph_gen.overappr_graph results/$*/merged-cfg.json \
	  --nofork \
	  --sof_cfi results/$*/oagraph/sof_cfi.csv

results/%/oagraph/no_cfi.csv &: \
	results/%/merged-cfg.json oagraph_gen/*.py

	mkdir -p results/$*/oagraph
	python3 -B -m oagraph_gen.overappr_graph results/$*/merged-cfg.json \
	  --nofork \
	  --no_cfi results/$*/oagraph/no_cfi.csv



results/%/oametrics/baseline.json: results/%/oagraph/base.json results/%/oagraph/baseline.csv oagraph_eval/*.py
	mkdir -p results/$*/oametrics
	python3 -B -m oagraph_eval.oagraph_eval results/$*/oagraph/base.json results/$*/oagraph/baseline.csv $@

results/%/oametrics/num_bd_cfi.json: results/%/oagraph/base.json results/%/oagraph/num_bd_cfi.csv oagraph_eval/*.py
	mkdir -p results/$*/oametrics
	python3 -B -m oagraph_eval.oagraph_eval results/$*/oagraph/base.json results/$*/oagraph/num_bd_cfi.csv $@

results/%/oametrics/num_id_cfi.json: results/%/oagraph/base.json results/%/oagraph/num_id_cfi.csv oagraph_eval/*.py
	mkdir -p results/$*/oametrics
	python3 -B -m oagraph_eval.oagraph_eval results/$*/oagraph/base.json results/$*/oagraph/num_id_cfi.csv $@

results/%/oametrics/type_cfi.json: results/%/oagraph/base.json results/%/oagraph/type_cfi.csv oagraph_eval/*.py
	mkdir -p results/$*/oametrics
	python3 -B -m oagraph_eval.oagraph_eval results/$*/oagraph/base.json results/$*/oagraph/type_cfi.csv $@

results/%/oametrics/num_bd_type_cfi.json: results/%/oagraph/base.json results/%/oagraph/num_bd_type_cfi.csv oagraph_eval/*.py
	mkdir -p results/$*/oametrics
	python3 -B -m oagraph_eval.oagraph_eval results/$*/oagraph/base.json results/$*/oagraph/num_bd_type_cfi.csv $@

results/%/oametrics/num_id_type_cfi.json: results/%/oagraph/base.json results/%/oagraph/num_id_type_cfi.csv oagraph_eval/*.py
	mkdir -p results/$*/oametrics
	python3 -B -m oagraph_eval.oagraph_eval results/$*/oagraph/base.json results/$*/oagraph/num_id_type_cfi.csv $@

results/%/oametrics/numarg_cfi.json: results/%/oagraph/base.json results/%/oagraph/numarg_cfi.csv oagraph_eval/*.py
	mkdir -p results/$*/oametrics
	python3 -B -m oagraph_eval.oagraph_eval results/$*/oagraph/base.json results/$*/oagraph/numarg_cfi.csv $@

results/%/oametrics/sof_cfi.json: results/%/oagraph/base.json results/%/oagraph/sof_cfi.csv oagraph_eval/*.py
	mkdir -p results/$*/oametrics
	python3 -B -m oagraph_eval.oagraph_eval results/$*/oagraph/base.json results/$*/oagraph/sof_cfi.csv $@

results/%/oametrics/no_cfi.json: results/%/oagraph/base.json results/%/oagraph/no_cfi.csv oagraph_eval/*.py
	mkdir -p results/$*/oametrics
	python3 -B -m oagraph_eval.oagraph_eval results/$*/oagraph/base.json results/$*/oagraph/no_cfi.csv $@




results/%/oaothmetrics/baseline.json: results/%/oagraph/base.json results/%/oagraph/baseline.csv results/%/map.json oagraph_eval/*.py
	mkdir -p results/$*/oaothmetrics
	python3 -B -m oagraph_eval.othermetrics results/$*/oagraph/base.json results/$*/oagraph/baseline.csv results/$*/map.json $@

results/%/oaothmetrics/num_bd_cfi.json: results/%/oagraph/base.json results/%/oagraph/num_bd_cfi.csv results/%/map.json oagraph_eval/*.py
	mkdir -p results/$*/oaothmetrics
	python3 -B -m oagraph_eval.othermetrics results/$*/oagraph/base.json results/$*/oagraph/num_bd_cfi.csv results/$*/map.json $@

results/%/oaothmetrics/num_id_cfi.json: results/%/oagraph/base.json results/%/oagraph/num_id_cfi.csv results/%/map.json oagraph_eval/*.py
	mkdir -p results/$*/oaothmetrics
	python3 -B -m oagraph_eval.othermetrics results/$*/oagraph/base.json results/$*/oagraph/num_id_cfi.csv results/$*/map.json $@

results/%/oaothmetrics/type_cfi.json: results/%/oagraph/base.json results/%/oagraph/type_cfi.csv results/%/map.json oagraph_eval/*.py
	mkdir -p results/$*/oaothmetrics
	python3 -B -m oagraph_eval.othermetrics results/$*/oagraph/base.json results/$*/oagraph/type_cfi.csv results/$*/map.json $@

results/%/oaothmetrics/num_bd_type_cfi.json: results/%/oagraph/base.json results/%/oagraph/num_bd_type_cfi.csv results/%/map.json oagraph_eval/*.py
	mkdir -p results/$*/oaothmetrics
	python3 -B -m oagraph_eval.othermetrics results/$*/oagraph/base.json results/$*/oagraph/num_bd_type_cfi.csv results/$*/map.json $@

results/%/oaothmetrics/num_id_type_cfi.json: results/%/oagraph/base.json results/%/oagraph/num_id_type_cfi.csv results/%/map.json oagraph_eval/*.py
	mkdir -p results/$*/oaothmetrics
	python3 -B -m oagraph_eval.othermetrics results/$*/oagraph/base.json results/$*/oagraph/num_id_type_cfi.csv results/$*/map.json $@

results/%/oaothmetrics/numarg_cfi.json: results/%/oagraph/base.json results/%/oagraph/numarg_cfi.csv results/%/map.json oagraph_eval/*.py
	mkdir -p results/$*/oaothmetrics
	python3 -B -m oagraph_eval.othermetrics results/$*/oagraph/base.json results/$*/oagraph/numarg_cfi.csv results/$*/map.json $@

results/%/oaothmetrics/sof_cfi.json: results/%/oagraph/base.json results/%/oagraph/sof_cfi.csv results/%/map.json oagraph_eval/*.py
	mkdir -p results/$*/oaothmetrics
	python3 -B -m oagraph_eval.othermetrics results/$*/oagraph/base.json results/$*/oagraph/sof_cfi.csv results/$*/map.json $@

results/%/oaothmetrics/no_cfi.json: results/%/oagraph/base.json results/%/oagraph/no_cfi.csv results/%/map.json oagraph_eval/*.py
	mkdir -p results/$*/oaothmetrics
	python3 -B -m oagraph_eval.othermetrics results/$*/oagraph/base.json results/$*/oagraph/no_cfi.csv results/$*/map.json $@


results/%/oagraph/all: \
results/%/oagraph/baseline.csv \
results/%/oagraph/num_bd_cfi.csv \
results/%/oagraph/type_cfi.csv \
results/%/oagraph/num_bd_type_cfi.csv \
results/%/oagraph/numarg_cfi.csv \
results/%/oagraph/sof_cfi.csv \
results/%/oagraph/no_cfi.csv
	@true


results/%/oametrics/all: \
results/%/oametrics/baseline.json \
results/%/oametrics/num_bd_cfi.json \
results/%/oametrics/type_cfi.json \
results/%/oametrics/num_bd_type_cfi.json \
results/%/oametrics/numarg_cfi.json \
results/%/oametrics/sof_cfi.json \
results/%/oametrics/no_cfi.json
	@true


results/%/oaothmetrics/all: \
results/%/oaothmetrics/baseline.json \
results/%/oaothmetrics/num_bd_cfi.json \
results/%/oaothmetrics/type_cfi.json \
results/%/oaothmetrics/num_bd_type_cfi.json \
results/%/oaothmetrics/numarg_cfi.json \
results/%/oaothmetrics/sof_cfi.json \
results/%/oaothmetrics/no_cfi.json
	@true








decache:
	find . -name __pycache__ -type d -exec rm -r {} +