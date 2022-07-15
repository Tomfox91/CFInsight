from itertools import chain
import csv
import networkx as nx
from tqdm import tqdm
import oagraph_eval.metric as mt
from oagraph_gen.graph_maker import ensure_edge_props
from common import wjson, rjson, print_state, Hex



def wmetricnodes(g, f):
	wjson(
		{n: {
			'addr': n,
			**{k: v for k, v in g.nodes[n].items()},
			'out_edge_props': {
				'hows': set(chain(*(g.edges[e].get('how', ('oa',)) for e in g.out_edges(n)))),
				'types': {g.edges[e].get('type', 'oa') for e in g.out_edges(n)},
			}
		} for n in g.nodes if n not in {'any', 'target'} and 'metrics' in g.nodes[n]},
		f)


def wc_l(f):
	import subprocess
	p = subprocess.run(['wc', '-l', f], capture_output=True, text=True)
	return int(p.stdout.split(' ')[0])


def generate_graph(basef, oasf):
	assert isinstance(basef, str) or hasattr(basef, 'read')
	print_state('Loading graph', basef)
	js = rjson(basef)


	g = nx.DiGraph()

	for bba, bb in tqdm(js['blocks'].items(), desc='Loading base graph'):
		assert bb['addr'] == bba, breakpoint()
		assert isinstance(bba, Hex) or bba == 'target'
		
		oe = bb['out_edges']
		del bb['out_edges']

		g.add_node(bba, **bb)

		for e in oe:
			assert isinstance(e['to'], Hex) or e['to'] == 'target'
			assert e['to'] in js['blocks'], f"{e['to']} is missing (from {bb['addr']})"

			to = e['to']
			del e['to']
			g.add_edge(bba, to, **e)
	
	print(f"Base: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")

	reader = csv.reader(oasf)
	for f, t in tqdm(reader, total=wc_l(oasf.name), desc='Loading extra edges'):
		if f.startswith('0x'):
			f = Hex(f)
		if t.startswith('0x'):
			t = Hex(t)
		assert f in js['blocks'] or f == 'any' or f.startswith('virtual'), f"{f} is missing (from OA {f} -> {t})"
		assert t in js['blocks'] or t in {'target', 'any'} or t.startswith('virtual'), f"{t} is missing (from OA {f} -> {t})"
		g.add_edge(f, t)

	ensure_edge_props(g, (e for e in g.edges() if e[1] != 'target'))

	print(f"OA: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")

	return g, js['functions']



if __name__ == '__main__':
	import argparse

	print_state('Init')

	parser = argparse.ArgumentParser(
		description='Evaluate metrics on a (possibly overapproximated) CFG',
	)
	parser.add_argument('input_cfg', help='Input CFG', type=argparse.FileType('r'))
	parser.add_argument('extra_edges', help='Extra edges', type=argparse.FileType('r'))

	parser.add_argument("output_cfg", help="Output JSON file", type=argparse.FileType('w'))

	apns = parser.parse_args()

	g, fns = generate_graph(apns.input_cfg, apns.extra_edges)

	mt.compute_metrics_graph(g)
	print_state('Writing graph', g)
	wmetricnodes(g, apns.output_cfg)

	print_state('End')







#
