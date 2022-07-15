from collections import Counter
from common import rjson, wjson




def count_types(cfg):
	succ_types = Counter()

	for bb in cfg.values():
		for _, t in bb['angr_successors']:
			succ_types[t] += 1

	return succ_types


def remove_unneeded_succtypes(cfg):
	for bb in cfg.values():
		bb['angr_successors'] = [[a, t] for a, t in bb['angr_successors'] if t not in {'Ijk_Ret', 'Ijk_Sys_syscall'}]
		bb['angr_predecessors'] = [[a, t] for a, t in bb['angr_predecessors'] if t not in {'Ijk_Ret', 'Ijk_Sys_syscall'}]


def ck_missing(cfg):
	for bb in cfg.values():
		assert 'addr' in bb, breakpoint()
		assert 'size' in bb, breakpoint()
		assert 'fn_addrs' in bb, breakpoint()
		assert 'angr_successors' in bb, breakpoint()
		assert 'angr_predecessors' in bb, breakpoint()
		for a, _ in bb['angr_successors']:
			assert a in cfg, breakpoint()


def simplify(cfg):
	ctr = 0
	tcks = set(cfg.keys())
	while tcks:
		tck = tcks.pop()
		sss = cfg[tck]['angr_successors']
		if (
			len(sss) == 1 and
			sss[0][1] == 'Ijk_Boring' and
			sss[0][0] == cfg[tck]['addr'] + cfg[tck]['size']):

			snd = sss[0][0]
			ssp = cfg[snd]['angr_predecessors']
			if len(ssp) == 1 and ssp[0][0] == tck and ssp[0][1] in {'Ijk_Boring', 'Ijk_InvalICache'}:

				cfg[tck]['size'] += cfg[snd]['size']
				cfg[tck]['angr_successors'] = cfg[snd]['angr_successors']
				tcks.add(tck)
				if snd in tcks:
					tcks.remove(snd)
				del cfg[snd]
				ctr += 1
	print(f"simplify: {ctr} nodes removed")


def lint_cfg(cfg):
	print(count_types(cfg))
	remove_unneeded_succtypes(cfg)
	ck_missing(cfg)
	simplify(cfg)
	print(count_types(cfg))
	return cfg


if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(
		description='Organize angr CFG',
	)
	parser.add_argument('input', type=argparse.FileType('r'))
	parser.add_argument('output', type=argparse.FileType('w'))

	apns = parser.parse_args()

	wjson(lint_cfg(rjson(apns.input)['blocks']), apns.output)
















#
