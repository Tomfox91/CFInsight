from tqdm import tqdm
import networkx as nx
from common import rjson, print_state, Hex, optintern
# from angrmgmt.loader import load_angr_proj






def generate_graph(inf, mappf=None, bindir=None):
	# print_state('Reading map file')
	# mapp = rjson(mappf)

	assert isinstance(inf, str) or hasattr(inf, 'read')
	print_state('Loading graph', inf)
	js = rjson(inf)

	# print_state('Loading binaries into angr')
	# proj = load_angr_proj(mapp, bindir)

	g = nx.DiGraph()

	for bba, bb in tqdm(js['blocks'].items(), desc='Loading graph'):
		assert bb['addr'] == bba
		assert isinstance(bba, Hex)
		bbprop = {
			'size': bb['size'],
			'num_instr': len(bb['instr_sizes']),
			'fn_addrs': frozenset(bb['fn_addrs']),
			'found_by': frozenset(bb['found_by']),
			'end_insn_indir': optintern(bb['end_insn_indir']),  # premature optimization
			'binary_basename': optintern(bb['binary_basename']),  # (root of all evil)
		}

		if bb.get('in_plt', False):
			bbprop['in_plt'] = bb['in_plt']

		if bb.get('fake_instr_sizes', False):
			# if exact number unknown, estimate assuming average length of 5
			# (fair assumption for complex code that breaks angr disassembly)
			bbprop['fake_instr_sizes'] = True
			bbprop['num_instr'] = bb['size'] // 5

		g.add_node(bba, **bbprop)

		for e in bb['out_edges']:
			assert isinstance(e['to'], Hex)
			assert e['to'] in js['blocks'], f"{e['to']} is missing (from {bb['addr']})"

			eprop = {
				'type': e['type'],
				'how': frozenset(e['how']),
			}
			g.add_edge(bba, e['to'], **eprop)

	ensure_edge_props(g, g.edges())

	return g, js['functions']



def ensure_edge_props(g, edges):
	for f, t in edges:
		assert t != 'target', breakpoint()
		if isinstance(t, str) and (t == 'any' or t.startswith('virtual')):
			g.edges[f, t]['distance'] = 0
			g.edges[f, t]['child_num_instr'] = 0
		else:
			# g.edges[f, t]['parent_num_instr'] = g.nodes[f]['num_instr']
			g.edges[f, t]['child_num_instr'] = g.nodes[t]['num_instr']



def add_target(g):
	g.add_node('target')

	for b, eii in g.nodes('end_insn_indir'):
		if eii == 'syscall':
			g.add_edge(
				b, 'target',
				distance=0,
				parent_num_instr=g.nodes[b]['num_instr'],
				child_num_instr=0)

	# g.add_node('library')
	# g.add_edge('library', 'target')
	# for f, t in g.edges:
	# 	if g.nodes[f]['binary_basename'] != g.nodes[t]['binary_basename']:
	# 		g.add_edge(f, 'library')



if __name__ == '__main__':
	import argparse
	from graph_algorithms import digraph_ancestors_dfs, digraph_descendants_dfs
	import timeit

	parser = argparse.ArgumentParser(
		description='Load merged CFG',
		# formatter_class=argparse.ArgumentDefaultsHelpFormatter
	)
	parser.add_argument('--map', help='Map file', type=argparse.FileType('r'))
	parser.add_argument('cfg', help='Merged CFGs', type=argparse.FileType('r'))
	parser.add_argument('--binarydir', help='Directory binaries')
	apns = parser.parse_args()
	g = generate_graph(apns.map, apns.cfg, apns.binarydir)
	add_target(g)

	print("Target predecessors:", len(digraph_ancestors_dfs(g, 'target')), g.number_of_nodes())
	print("0x23E000 successors:", len(digraph_descendants_dfs(g, 0x23E000)), g.number_of_nodes())
	print("Time for digraph_ancestors_dfs:", timeit.timeit(lambda: digraph_ancestors_dfs(g, 'target'), number=100) / 100.)
	print("Time for digraph_descendants_dfs:", timeit.timeit(lambda: digraph_descendants_dfs(g, 0x23E000), number=100) / 100.)




#
