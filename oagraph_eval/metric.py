import os
import math
import networkx as nx
from tqdm import tqdm
import psutil
from multiprocessing import Pool
from graph_algorithms import digraph_ancestors_dfs
from common import Hex



class Intersector:
	"""Compute the set of nodes between a node and the target"""
	
	def __init__(self, graph, target):
		self.g = graph
		self.target = target
		self._target_ancestors = digraph_ancestors_dfs(self.g, self.target)
		self._any_subgraph = None

	def _ascendent_descendants_dfs(self, node):
		visited = {node}
		stack = [iter(self.g.successors(node))]
		while stack and len(visited) < 25000:
			children = stack[-1]
			try:
				child = next(children)
				if child in visited or child not in self._target_ancestors:
					continue
				else:
					visited.add(child)
					stack.append(iter(self.g.successors(child)))
			except StopIteration:
				stack.pop()

		assert "target" in visited

		return visited

	def get_subgraph(self, node):
		if node == 'any':
			if self._any_subgraph is None:
				self._any_subgraph = self.g.subgraph(self._target_ancestors).copy()
			return self._any_subgraph
		else:
			return self.g.subgraph(self._ascendent_descendants_dfs(node))



def mccabe(subgraph):  # E − N + 2
	ret = subgraph.number_of_edges() - subgraph.number_of_nodes() + 2

	for pvn in subgraph.nodes:
		if isinstance(pvn, str) and (pvn == 'any' or pvn.startswith('virtual')):
			ret += - subgraph.out_degree(pvn) - subgraph.in_degree(pvn) + 1
			ret += subgraph.out_degree(pvn) * subgraph.in_degree(pvn)

	return ret


def dist(distances, node, **_):
	return distances.get(node, math.inf)


def dist_div_mccabe(distances, node, subgraph, **_):
	if node not in distances:
		return math.inf
	else:
		return distances[node] / mccabe(subgraph)


def dist_div_log_mccabe(distances, node, subgraph, **_):
	if node not in distances:
		return math.inf
	else:
		return distances[node] / math.log(1 + mccabe(subgraph))


metrics = {
	'blockdist': lambda instr_distances, block_distances, **_: dist(distances=block_distances, **_),
	'instrdist': lambda instr_distances, block_distances, **_: dist(distances=instr_distances, **_),
	'mccabe': lambda subgraph, **_: mccabe(subgraph) if subgraph is not None else None,
	'blockdist_div_mccabe': lambda instr_distances, block_distances, **_: dist_div_mccabe(distances=block_distances, **_),
	'blockdist_div_log_mccabe': lambda instr_distances, block_distances, **_: dist_div_log_mccabe(distances=block_distances, **_),
	'instrdist_div_mccabe': lambda instr_distances, block_distances, **_: dist_div_mccabe(distances=instr_distances, **_),
	'instrdist_div_log_mccabe': lambda instr_distances, block_distances, **_: dist_div_log_mccabe(distances=instr_distances, **_),
}



def indirect_call_nodes(g):
	return [n for n, eii in g.nodes('end_insn_indir') if eii == 'call_indirect']


def initializer(*args):
	global glbl
	glbl = args



def compute_metrics_node(n):
	global glbl
	g, inter, idist, bdist = glbl
	ret = {}
	if 'any' in g.successors(n):
		subgraph = inter.get_subgraph('any')
	elif n in bdist:
		subgraph = inter.get_subgraph(n)
	else:
		subgraph = None
	for mn, m in metrics.items():
		ret[mn] = m(
			intersector=inter,
			subgraph=subgraph,
			instr_distances=idist,
			block_distances=bdist,
			node=n)

	return (n, ret)


def num_programs_running():
	i = 0
	my_cmdline = psutil.Process().cmdline()
	for p in psutil.process_iter(attrs=['cmdline']):
		c = p.info['cmdline']
		if c[:4] == my_cmdline[:4]:
			if p.parent().cmdline() != c:
				i += 1
	if not i:
		breakpoint()
	return i


def compute_metrics_graph(g, target='target'):
	i = Intersector(g, target)

	idist = nx.shortest_path_length(g, target=target, weight='child_num_instr')
	bdist = nx.shortest_path_length(g, target=target, weight='distance')

	nodes = indirect_call_nodes(g)  # [:5]
	assert isinstance(nodes, list)
	assert all(isinstance(n, Hex) for n in nodes)

	core_count = psutil.cpu_count()
	core_count = min(core_count, int(os.getenv('CBCH_MAXCORES', psutil.cpu_count())))
	core_count = min(core_count, len(nodes) // 20)
	initargs = (g, i, idist, bdist)

	bar = tqdm(total=len(nodes), desc=f"Computing metrics ({core_count}t)")

	with Pool(core_count, initializer, initargs) as pool:
		for nd, mtrcs in pool.imap_unordered(compute_metrics_node, nodes):
			g.nodes[nd]['metrics'] = {}
			for mn, mv in mtrcs.items():
				g.nodes[nd]['metrics'][mn] = mv
			bar.update()
	bar.close()

#
