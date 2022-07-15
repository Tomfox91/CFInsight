import gc
import os
import sys
import csv
import oagraph_gen.overappr_edges as oa
import oagraph_gen.graph_maker as gm
from tqdm import tqdm
from common import wjson, print_state, jsonpreprocess


def node_to_json(g, n):
	return {
		'addr': jsonpreprocess(n),
		**{jsonpreprocess(k): jsonpreprocess(v) for k, v in g.nodes[n].items()},
		'out_edges': [
			{
				'to': jsonpreprocess(t),
				**{jsonpreprocess(k): jsonpreprocess(v) for k, v in g.edges[n, t].items() if k != 'child_num_instr'}
			} for t in g.successors(n)
		]
	}


def graph_to_json(g):
	return {jsonpreprocess(n): node_to_json(g, n) for n in g.nodes}


def wgraph(g, fns, f):
	wjson({
		'blocks': graph_to_json(g),
		'functions': fns
	}, f, skip_preprocess=True)


def wextra(oas, f):
	writer = csv.writer(f)

	for ee in tqdm(oas, desc='CSV'):
		writer.writerow(ee)


# def wmetricnodes(g, f):
# 	wjson({n: {
# 		'addr': n,
# 		**{k: v for k, v in g.nodes[n].items()}
# 	} for n in g.nodes if 'metrics' in g.nodes[n]}, f)



if __name__ == '__main__':
	import argparse

	print_state('Init')

	parser = argparse.ArgumentParser(
		description='Generate overapproximated graphs from a merged CFG',
		# formatter_class=argparse.ArgumentDefaultsHelpFormatter
	)
	parser.add_argument('input_cfg', help='Input CFG', type=argparse.FileType('r'))
	# parser.add_argument('map', help='Map file', type=argparse.FileType('r'))
	# parser.add_argument('binarydir', help='Directory binaries')

	parser.add_argument(
		f"--basegraph", help=f"Output JSON file with common properties",
		type=argparse.FileType('w'), metavar=f"final.json")

	parser.add_argument('--nofork', help='Save memory', action='store_true')

	grp = parser.add_argument_group('Overapproximations generation')
	extras = set()

	for oan, oas in oa.overapproximation_fns.items():
		grp.add_argument(
			f"--{oan}",
			help=f"Output OA file for {oan}{'. Requires: ' if oas.extra_cmdlineargs else ''}{', '.join(oas.extra_cmdlineargs)}",
			type=argparse.FileType('w'), metavar=f"{oan.replace('_cfi', '')}.csv")
		# grp.add_argument(
		# 	f"--{oan}", help=f"Output JSON files for {oan}",
		# 	nargs=2, metavar=('FULL', 'ONLYMETRIC'),
		# 	type=argparse.FileType('w'))

		for ea in oas.extra_cmdlineargs:
			if ea not in extras:
				grp.add_argument(
					f"--{ea}",
					type=(argparse.FileType('r') if ea.endswith('_file') else str))
				extras.add(ea)


	apns = parser.parse_args()

	g, fns = gm.generate_graph(apns.input_cfg)
	gm.add_target(g)
	overapproxs = oa.overapproximations(g=g, fns=fns, apns=apns)

	if apns.basegraph:
		print_state('Writing graph', 'base')
		wgraph(g, fns, apns.basegraph)

	children = []

	for oan in oa.overapproximation_fns.keys():
		outfile = getattr(apns, oan)
		if outfile:
			oag = overapproxs[oan]()
			if apns.nofork:
				# print_state(oan, f"GC")
				# del overapproxs
				# del g
				# gc.collect()
				print_state(oan, f"Writing graph")
				wextra(oag, outfile)
				print_state(oan, f"Written graph")

			else:
				print_state(oan, f"GC")
				gc.collect()
				# mt.compute_metrics(oag)
				cpid = os.fork()
				if cpid == 0:  # child
					wextra(oag, outfile)
					print_state(oan, f"Written graph in fork {os.getpid()}")
					sys.exit(0)
				
				else:  # main process
					print_state(oan, f"Forked process {cpid} and writing graph")
					children.append(cpid)
					# overapproxs[oan].reset()
					# gc.collect()
					continue

	for cpid in children:
		assert 0 == os.waitstatus_to_exitcode(os.waitpid(cpid, 0)[1])
	
	print_state('End')




	# print(repr(overapproxs['baseline']()))
	# print(repr(overapproxs['no_cfi']()))
	# print(repr(overapproxs['sof_cfi']()))
	# print(repr(overapproxs['num_bd_cfi']()))








#
