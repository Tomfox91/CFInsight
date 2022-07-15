from tqdm import tqdm
from .loader import load_angr_proj
from common import Hex, rjson, wjson


if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(
		description='Extract CFG using angr',
	)
	parser.add_argument('mapfile', help='Input mapfile', type=argparse.FileType('r'))
	parser.add_argument('binarydir', help='Directory binaries')
	parser.add_argument('output', help='Output CFG file', type=argparse.FileType('w'))

	grp = parser.add_mutually_exclusive_group(required=True)
	grp.add_argument('--only_main', action='store_true')
	grp.add_argument('--all_libs', action='store_true')

	grp = parser.add_mutually_exclusive_group(required=True)
	grp.add_argument('--fast', action='store_true')
	grp.add_argument('--emulated', action='store_true')

	grp = parser.add_mutually_exclusive_group(required=True)
	grp.add_argument('--with_simpro', action='store_true')
	grp.add_argument('--without_simpro', action='store_true')

	apns = parser.parse_args()
	assert apns.only_main ^ apns.all_libs, breakpoint()
	assert apns.fast ^ apns.emulated, breakpoint()
	assert apns.with_simpro ^ apns.without_simpro, breakpoint()


	mapp = rjson(apns.mapfile)
	apns.mapfile.close()
	proj = load_angr_proj(mapp, apns.binarydir, only_main=apns.only_main, use_sim_procedures=apns.with_simpro)


	exec_sections = []
	for l in proj.loader.all_elf_objects:
		for sec in l.sections_map.values():
			if sec.is_executable:
				exec_sections.append(sec)

	if apns.fast:
		cfg = proj.analyses.CFGFast(force_complete_scan=False, show_progressbar=True)
	else:
		cfg = proj.analyses.CFGEmulated(keep_state=False, show_progressbar=True)


	fns = {}
	for fna, fn in tqdm(cfg.kb.functions.items(), desc="Processing functions"):
		if not fn.is_simprocedure:
			assert fna == fn.addr
			assert fna not in fns
			fns[Hex(fna)] = {
				'addr': Hex(fn.addr),
				'name': fn.name,
				'binary_name': fn.binary_name
			}

	
	skipped_noexec = []
	skipped_noblock = []
	dct = {}
	for bb in tqdm(cfg.graph.nodes, desc="Processing blocks"):
		for xsec in exec_sections:
			if xsec.contains_addr(bb.addr):
				break
		else:
			skipped_noexec.append(bb)
			continue

		if not bb.block:
			skipped_noblock.append(bb)
			continue

		if Hex(bb.addr) in dct:
			assert dct[bb.addr]['addr'] == bb.addr
			assert dct[bb.addr]['size'] == bb.size
			dct[bb.addr]['fn_addrs'].add(Hex(bb.function_address))
			dct[bb.addr].setdefault('instances', 0)
			dct[bb.addr]['instances'] += 1
		else:
			dct[Hex(bb.addr)] = {
				'addr': Hex(bb.addr),
				'size': bb.size,
				'fn_addrs': {Hex(bb.function_address)},
				'angr_successors': set(),
				'angr_predecessors': set(),
			}

		dct[bb.addr]['angr_successors'].update((Hex(sbb.addr), t) for sbb, t in bb.successors_and_jumpkinds() if sbb.block)
		dct[bb.addr]['angr_predecessors'].update((Hex(pbb.addr), t) for pbb, t in bb.predecessors_and_jumpkinds() if pbb.block)

	print(f"skipped_noexec: {len(skipped_noexec)}; skipped_noblock: {len(skipped_noblock)}")

	wjson({
		'functions': fns,
		'blocks': dct
	}, apns.output)

#
