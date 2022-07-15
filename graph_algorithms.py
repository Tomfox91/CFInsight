from collections import deque, defaultdict


def filter_paths_bfs(G, target, pfilter, depth_limit=None):
	"""Iterate over paths in a breadth-first search.
	Return paths for which pfilter() returns True.
	If pfilter() returns True or False, subpaths are not explored.
	"""
	# Based on generic_bfs_edges from networkx
	# https://networkx.github.io/documentation/stable/_modules/networkx/algorithms/traversal/breadth_first_search.html#bfs_edges

	# visited = {target} <- we don't keep track of visited nodes because we want to examine every path
	forbiddenpaths = defaultdict(set)  # forbiddenpaths[l] -> forbidden paths with length l
	if depth_limit is None:
		depth_limit = len(G)
	queue = deque([((target,), target, depth_limit, G.predecessors(target))])
	while queue:
		path, parent, depth_now, children = queue[0]
		try:
			child = next(children)
			if child in path:
				pass
			else:
				path = (child,) + path
				f = pfilter(path)
				if f is True:
					forbiddenpaths[len(path)].add(path)
				elif f is False:
					pass
				elif depth_now > 1:
					queue.append((path, child, depth_now - 1, G.predecessors(child)))
		except StopIteration:
			queue.popleft()
	return forbiddenpaths





def digraph_ancestors_dfs(G, target, forbiddenpaths={}):
	"""Get ancestors of target in G, excluding paths with certain endings.
	forbiddenpaths must be a dict: len(paths) -> set of paths."""
	# Based on dfs_labeled_edges from networkx
	# https://networkx.github.io/documentation/stable/_modules/networkx/algorithms/traversal/depth_first_search.html#dfs_labeled_edges
	# Based on http://www.ics.uci.edu/~eppstein/PADS/DFS.py
	# by D. Eppstein, July 2004.


	if __debug__:
		for i in forbiddenpaths:
			for p in forbiddenpaths[i]:
				assert len(p) == i

	visited = set()
	visited.add(target)
	max_forbiddenpath_length = max([0] + list(forbiddenpaths.keys()))
	# print(f"max_forbiddenpath_length: {max_forbiddenpath_length}")
	stack = [(False, (target,), target, iter(G.predecessors(target)))]
	while stack:
		fasttrack, path, parent, children = stack[-1]
		try:
			child = next(children)
			if child in visited:
				continue

			if not fasttrack:
				assert path is not None
				path = (child,) + path
				path_len = len(path)
				if len(path) > max_forbiddenpath_length:
					fasttrack = True

			if fasttrack:
				visited.add(child)
				stack.append((True, None, child, iter(G.predecessors(child))))

			elif path_len in forbiddenpaths and path in forbiddenpaths[path_len]:
				continue

			else:
				visited.add(child)
				stack.append((False, path, child, iter(G.predecessors(child))))

		except StopIteration:
			stack.pop()

	return visited


def digraph_descendants_dfs(G, node):
	"""Get descendants of node in G."""
	# Based on dfs_labeled_edges from networkx
	# https://networkx.github.io/documentation/stable/_modules/networkx/algorithms/traversal/depth_first_search.html#dfs_labeled_edges
	# Based on http://www.ics.uci.edu/~eppstein/PADS/DFS.py
	# by D. Eppstein, July 2004.

	visited = set()
	visited.add(node)
	stack = [iter(G.successors(node))]
	while stack:
		children = stack[-1]
		try:
			child = next(children)
			if child in visited:
				continue
			visited.add(child)
			stack.append(iter(G.successors(child)))

		except StopIteration:
			stack.pop()

	return visited


if __name__ == '__main__':
	import networkx as nx
	import tqdm
	import timeit
	
	print("Testing digraph_ancestors_dfs against nx.dfs_postorder_nodes")

	for i in tqdm.trange(1000):
		g = nx.fast_gnp_random_graph(80, .05, directed=True)
		da = frozenset(digraph_ancestors_dfs(g, 0))
		dpn = frozenset(nx.dfs_postorder_nodes(g.reverse(copy=False), 0))
		assert da == dpn, (da, dpn, da - dpn, dpn - da)
	del da, dpn

	
	print("Testing performance of digraph_ancestors_dfs")

	tda = timeit.timeit(lambda: digraph_ancestors_dfs(g, 0), number=10000)
	print("digraph_ancestors_dfs:", tda)
	tdpn = timeit.timeit(lambda: list(nx.dfs_postorder_nodes(g.reverse(copy=False), 0)), number=10000)
	print("nx.dfs_postorder_nodes:", tdpn, f"{tdpn/tda*100}%")
	del g

	print("Testing forbiddenpaths in digraph_ancestors_dfs")
	G = nx.DiGraph()
	G.add_edges_from(((0, 1), (0, 2), (1, 4), (2, 3), (3, 1), (3, 6), (4, 5), (4, 7), (5, 3), (5, 6), (6, 8), (6, 9), (7, 8), (8, 'T'), (9, 8)))

	assert set(digraph_ancestors_dfs(G, 'T', {2: {(8, 'T')}})) == {'T'}
	assert set(digraph_ancestors_dfs(G, 'T', {3: {(9, 8, 'T')}})) == set(G.nodes()) - {9}
	assert set(digraph_ancestors_dfs(G, 'T', {3: {(6, 8, 'T')}})) == set(G.nodes())
	assert set(digraph_ancestors_dfs(G, 'T', {3: {(7, 8, 'T'), (6, 8, 'T')}})) == set(G.nodes()) - {7}
	assert set(digraph_ancestors_dfs(G, 'T', {3: {(6, 8, 'T'), (9, 8, 'T')}})) == set(G.nodes()) - {9, 6}
	assert set(digraph_ancestors_dfs(G, 'T', {3: {(6, 8, 'T'), (9, 8, 'T')}, 6: {(3, 1, 4, 7, 8, 'T')}})) == {0, 1, 4, 7, 8, 'T'}


	print("Testing filter_paths_bfs against nx.all_simple_paths")

	def pfilter(path):
		global paths
		paths.add(path)
	for i in tqdm.trange(100):
		paths = set()
		g = nx.fast_gnp_random_graph(10, .5, directed=True)
		filter_paths_bfs(g, 0, pfilter)
		asp = set()
		for s in g.nodes():
			asp.update(map(tuple, (nx.all_simple_paths(g, s, 0))))
		assert paths == asp
	del paths, asp, g

	print("Testing pfilter in filter_paths_bfs")

	gasp = set()
	for s in G.nodes():
		gasp.update(map(tuple, (nx.all_simple_paths(G, s, 'T'))))

	def pfilter(path):
		global paths
		paths.add(path)
		if path == (6, 9, 8, 'T'):
			return True
		elif path == (4, 7, 8, 'T'):
			return False
	paths = set()
	assert filter_paths_bfs(G, 'T', pfilter) == {4: {(6, 9, 8, 'T')}}
	assert paths - gasp == set()
	for mpath in gasp - paths:
		assert len(mpath) > 4
		assert mpath[-4:] in [(6, 9, 8, 'T'), (4, 7, 8, 'T')]
	del paths, mpath

	def pfilter(path):
		global paths
		paths.add(path)
		if path == (6, 9, 8, 'T'):
			return True
		elif path == (4, 7, 8, 'T'):
			return False
		elif path == (6, 8, 'T'):
			return True
	paths = set()
	assert filter_paths_bfs(G, 'T', pfilter) == {3: {(6, 8, 'T')}, 4: {(6, 9, 8, 'T')}}
	assert paths == {(9, 8, 'T'), (6, 8, 'T'), (8, 'T'), (7, 8, 'T'), (4, 7, 8, 'T'), (6, 9, 8, 'T')}
	del paths








#
