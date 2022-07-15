import argparse
from collections import defaultdict, namedtuple
from math import inf
from tqdm import tqdm
import networkx as nx
from .graph_maker import ensure_edge_props
from fntypes.function_types import FunctionTypes, FunctionNumArg
from fntypes.functioncalls_parser import FCManager
from common import print_state, rjson











class LazyRunner:
	def __init__(self, func, prints, *args, **kwargs):
		super(LazyRunner, self).__init__()
		self.func = func
		self.prints = prints
		self.args = args
		self.kwargs = kwargs
		self.run = False

	def __call__(self):
		if self.run is not True:
			assert self.run is not None
			self.run = None
			if self.prints:
				print_state(self.func.__name__, 'LR: Computing')
			self.result = self.func(*self.args, **self.kwargs)
			if self.prints:
				print_state(self.func.__name__, f"LR: Computed a {type(self.result)}")
			self.run = True
		return self.result

	def reset(self):
		del self.result
		self.run = False



def overapproximations(g: nx.DiGraph, **kwargs):
	comprop = precompute_common_properties(g, **kwargs)

	oa_edge_gens = {}
	legal_edges = set(g.edges())
	legal_nodes = set(g.nodes())
	gg = g.copy(as_view=True)

	for oan, oa in overapproximation_fns.items():
		oa_edge_gens[oan] = LazyRunner(oa.fn, True, g=gg, oa_edge_gens=oa_edge_gens, **comprop)

	del gg
	oaes = {}

	def mkoaes(oa_label, oa_edge_gen):
		oa_edges = oa_edge_gen()
		if not isinstance(oa_edges, set):
			oa_edges = set(oa_edges)
		oa_edges -= legal_edges
		# gg = g.copy()
		# print_state(oa_label, "Adding edges")
		# gg.add_edges_from(oa_edges)
		for n in set(s for _, s in oa_edges) - legal_nodes:
			assert n == 'any' or n.startswith('virtual'), breakpoint()
		# ensure_edge_props(gg, oa_edges)
		print_state(oa_label, "Computed overapproximation", f"overapproximated edges = {len(oa_edges)}")
		return oa_edges

	for oan in overapproximation_fns.keys():
		oaes[oan] = LazyRunner(mkoaes, False, oan, oa_edge_gens[oan])

	return oaes


def precompute_common_properties(g: nx.DiGraph, fns: dict, apns: argparse.Namespace, target='target'):


	kwargs = {'target': target, 'fns': fns, 'apns': apns}


	# indirect calls and targets
	print_state("Common properties", 'callers & targets')

	kwargs['indirect_function_callers'] = tuple(
		n for n, eii in g.nodes('end_insn_indir') if eii == 'call_indirect')

	kwargs['function_addrs'] = set(fns.keys()) & set(g.nodes)


	def pltoverrides(g):
		ret = {}
		for n, in_plt in g.nodes('in_plt', default=False):
			if in_plt:
				assert g.nodes[n]['end_insn_indir'] == 'jump_indirect', breakpoint()
				succ = tuple(g.successors(n))
				if not succ:
					continue
				if len(succ) > 1:
					succ = tuple(s for s in succ if 'cfggrind' in g.edges[n, s]['how'])
				assert len(succ) == 1, breakpoint()
				ret[n] = succ[0]
		return ret

	kwargs['pltoverrides'] = LazyRunner(pltoverrides, False, g)

	# for n in g.nodes:
	# 	assert 'indirect' in g.nodes[n], n
	# kwargs['indirect_bbs'] = set([n for n in g.nodes if g.nodes[n]['indirect']])
	# kwargs['indirect_targets'] = set([s for n in kwargs['indirect_bbs'] for s in g.successors(n)])

	# kwargs['function_callers'] = set()
	# kwargs['intrafunction_jumpers'] = set()
	# kwargs['non_trivial_successors'] = {}
	# kwargs['called_functions'] = set()

	# for n in kwargs['indirect_bbs']:
	# 	n_fns = g.nodes[n]['cfggrind_bb'].fns
	# 	non_trivial_successors = set(g.successors(n))
	# 	# possibly remove edge to bb following the current one, but only if they belong to the same function(s) and not in case of jmp
	# 	next_bb = n + g.nodes[n]['angr_bb'].size
	# 	if g.nodes[n]['end_insn_type'] == call_indirect and next_bb in g.nodes and g.nodes[next_bb]['cfggrind_bb'].fns & n_fns:
	# 		non_trivial_successors -= {next_bb}
	# 	del next_bb

	# 	all_function_calls = True
	# 	# can only be intrafunction jump if end insn is a jump (not call)
	# 	all_intrafunction_jumps = g.nodes[n]['end_insn_type'] == jump_indirect
	# 	nts_remove = set()
	# 	for s in non_trivial_successors:
	# 		if all_function_calls and s not in g.graph['functions']:
	# 			# indirect target is not start of a function.
	# 			if g.nodes[n]['end_insn_type'] == jump_indirect:
	# 				all_function_calls = False
	# 			elif g.nodes[n]['end_insn_type'] == call_indirect:
	# 				print(f"Warning: {n} calls into the middle of a function ({s}). longjmp?")
	# 				nts_remove.add(s)
	# 			else:
	# 				assert False

	# 		if all_intrafunction_jumps and g.nodes[s]['cfggrind_bb'].fns != n_fns:
	# 			# indirect target is not in the same function
	# 			all_intrafunction_jumps = False

	# 		if all_intrafunction_jumps and all_function_calls and s in g.graph['functions'] and g.nodes[s]['cfggrind_bb'].fns == n_fns:
	# 			# if both, decide from insn
	# 			if g.nodes[n]['end_insn_type'] == jump_indirect:
	# 				all_function_calls = False
	# 			elif g.nodes[n]['end_insn_type'] == call_indirect:
	# 				all_intrafunction_jumps = False
	# 			else:
	# 				assert False

	# 	non_trivial_successors -= nts_remove

	# 	if not non_trivial_successors:
	# 		# skip longjmp
	# 		fns = list(g.nodes[n]['cfggrind_bb'].fn_addrs)
	# 		assert len(fns) == 1, breakpoint()
	# 		assert g.graph['functions'][fns[0]].fn_name.endswith('::__longjmp'), breakpoint()
	# 		all_function_calls = False
	# 		all_intrafunction_jumps = True

	# 	# either one or the other
	# 	assert all_function_calls ^ all_intrafunction_jumps, breakpoint()
	# 	# if this fails, maybe check that LD_BIND_NOW was set during the run

	# 	kwargs['non_trivial_successors'][n] = non_trivial_successors

	# 	if all_function_calls:
	# 		kwargs['function_callers'].add(n)
	# 		kwargs['called_functions'].update(non_trivial_successors)

	# 	if all_intrafunction_jumps:
	# 		kwargs['intrafunction_jumpers'].add(n)

	# assert kwargs['function_callers'] | kwargs['intrafunction_jumpers'] == kwargs['indirect_bbs'], breakpoint()

	# print(f"BBs with indirect control flow transfers: {len(kwargs['indirect_bbs'])} (function calls: {len(kwargs['function_callers'])}, intra-function jumps: {len(kwargs['intrafunction_jumpers'])}), called functions: {len(kwargs['called_functions'])}, targets: {len(kwargs['indirect_targets'])}")





	# distance
	print_state("Common properties", 'distances')

	kwargs['block_distance'] = nx.shortest_path_length(g, target=target, weight='distance')
	kwargs['instr_distance'] = nx.shortest_path_length(g, target=target, weight='child_num_instr')

	for n in g.nodes:
		if n not in kwargs['block_distance']:
			assert n not in kwargs['instr_distance']
			kwargs['block_distance'][n] = inf
			kwargs['instr_distance'][n] = inf
		g.nodes[n]['block_distance'] = kwargs['block_distance'][n]
		g.nodes[n]['instr_distance'] = kwargs['instr_distance'][n]

	kwargs['block_distance_bins'] = defaultdict(list)
	kwargs['instr_distance_bins'] = defaultdict(list)
	for n, d in kwargs['block_distance'].items():
		# only allow function starts
		if n in kwargs['function_addrs']:
			kwargs['block_distance_bins'][d].append(n)
	for n, d in kwargs['instr_distance'].items():
		# only allow function starts
		if n in kwargs['function_addrs']:
			kwargs['instr_distance_bins'][d].append(n)

	return kwargs


# the functions below must return overapproximation edges that are introduced by various CFI policies


def baseline(**_):
	return ()


def num_cfi_naive(g, fns, target, indirect_function_callers, distance, distance_bins, **_):
	"""
	* numeric CFI -> enforces maximum decrement in distance to syscall
	* somehow define distance-to-syscall `d`
	* for every BB b:
		* let min_sd = min(d) over all non-follow successors
	* for any indirect call BB: enforce that callee has d >= min_sd
	"""

	ret = []

	for n in indirect_function_callers:
		lret = []
		min_sd = min([inf] + [
			distance[s] for s in g.successors(n)
			if g.edges[(n, s)]['type'] != 'follow'])
		for d in distance_bins.keys():
			if d >= min_sd:
				for pt in distance_bins[d]:
					lret.append((n, pt))
		ret.extend(lret)
	return ret


def num_cfi(g, fns, target, indirect_function_callers, distance, distance_bins, **_):
	ret = []

	for n in indirect_function_callers:
		min_sd = min([inf] + [
			distance[s] for s in g.successors(n)
			if g.edges[(n, s)]['type'] != 'follow'])
		for d in distance_bins.keys():
			if d >= min_sd:
				ret.append((n, f"virtual{d:03}"))

	for d in distance_bins.keys():
		for pt in distance_bins[d]:
			ret.append((f"virtual{d:03}", pt))

	# for n in indirect_function_callers:
	# 	min_sd = min([inf] + [
	# 		distance[s] for s in g.successors(n)
	# 		if g.edges[(n, s)]['type'] != 'follow'])
	# 	ret.append((n, f"virtual{min_sd}"))

	# for min_sd in distance_bins.keys():
	# 	for d in distance_bins.keys():
	# 		if d >= min_sd:
	# 			for pt in distance_bins[d]:
	# 				ret.append((f"virtual{min_sd}", pt))

	return ret


def num_bd_cfi_naive(
	block_distance, block_distance_bins,
	instr_distance, instr_distance_bins, **kwargs):
	return num_cfi_naive(
		distance=block_distance, distance_bins=block_distance_bins, **kwargs)


def num_id_cfi_naive(
	block_distance, block_distance_bins,
	instr_distance, instr_distance_bins, **kwargs):
	return num_cfi_naive(
		distance=instr_distance, distance_bins=instr_distance_bins, **kwargs)


def num_bd_cfi(
	block_distance, block_distance_bins,
	instr_distance, instr_distance_bins, **kwargs):
	return num_cfi(
		distance=block_distance, distance_bins=block_distance_bins, **kwargs)


def num_id_cfi(
	block_distance, block_distance_bins,
	instr_distance, instr_distance_bins, **kwargs):
	return num_cfi(
		distance=instr_distance, distance_bins=instr_distance_bins, **kwargs)





def numarg_cfi(g, indirect_function_callers, function_addrs, pltoverrides, apns, **_):
	"""
	like type CFI, but only considers number of args
	"""

	assert apns.dwarf_types_file, "No --dwarf_types_file provided"
	assert apns.fn_calls, "No --fn_calls provided"
	assert apns.map_file, "No --map_file provided"
	assert apns.bin_dir, "No --bin_dir provided"

	fna = FunctionNumArg(dwarftypesf=apns.dwarf_types_file, overrides=pltoverrides(), functions=function_addrs)
	fcma = FCManager(apns.fn_calls, rjson(apns.map_file), bindir=apns.bin_dir)

	ret = []
	anomalies = 0

	for n in tqdm(indirect_function_callers, desc='Call sites'):
		compiler_type = fcma.get_type(
			binname=g.nodes[n]['binary_basename'],
			addr=n)
		compiler_numarg = len(compiler_type) if compiler_type is not None else -1

		actual_numargs = set()

		for s in g.successors(n):
			t = g.edges[n, s]['type']
			assert t in {'call_indirect', 'follow', 'unknown'}, breakpoint()
			if t == 'call_indirect':
				assert s in function_addrs, breakpoint()
				actual_numargs.add(fna.numarg_of_function.get(s, -1))

		if compiler_numarg is not None:
			all_numargs = actual_numargs | {compiler_numarg}
		else:
			all_numargs = actual_numargs

		if actual_numargs and compiler_numarg and (len(actual_numargs) > 1 or compiler_numarg not in actual_numargs):
			anomalies += 1

		for na in all_numargs:
			same_numarg_targets = set(fna.functions_with_numargs({na}))
			assert(same_numarg_targets.issubset(set(g.nodes))), breakpoint()
			ret.extend([(n, f"virtual{na:02}")])
			ret.extend([(f"virtual{na:02}", s) for s in same_numarg_targets])
			# will be deduplicated later, so we don't care now

	print(f"Type anomalies: {anomalies} out of {len(indirect_function_callers)}")

	return ret




def type_cfi(g, indirect_function_callers, function_addrs, pltoverrides, apns, **_):
	"""
	type CFI
	"""

	assert apns.dwarf_types_file, "No --dwarf_types_file provided"
	assert apns.fn_calls, "No --fn_calls provided"
	assert apns.map_file, "No --map_file provided"
	assert apns.bin_dir, "No --bin_dir provided"

	ft = FunctionTypes(dwarftypesf=apns.dwarf_types_file, overrides=pltoverrides(), functions=function_addrs)
	fcma = FCManager(apns.fn_calls, rjson(apns.map_file), bindir=apns.bin_dir)

	ret = []
	anomalies = 0

	for n in tqdm(indirect_function_callers, desc='Call sites'):
		compiler_type = fcma.get_type(
			binname=g.nodes[n]['binary_basename'],
			addr=n)

		actual_types = set()

		for s in g.successors(n):
			t = g.edges[n, s]['type']
			assert t in {'call_indirect', 'follow', 'unknown'}, breakpoint()
			if t == 'call_indirect':
				assert s in function_addrs, breakpoint()
				actual_types.add(ft.type_of_function[s])

		if compiler_type is not None:
			all_types = actual_types | {compiler_type}
		else:
			all_types = actual_types

		if actual_types and compiler_type and (len(actual_types) > 1 or compiler_type not in actual_types):
			anomalies += 1

		same_type_targets = set(ft.functions_with_types(all_types))

		assert(same_type_targets.issubset(set(g.nodes))), breakpoint()


		ret.extend([(n, s) for s in same_type_targets])

	print(f"Type anomalies: {anomalies} out of {len(indirect_function_callers)}")

	return ret


def num_bd_type_cfi(g, oa_edge_gens, **kwargs):
	"""
	Trivial intersection of num_bd_cfi & type_cfi
	"""

	return set(oa_edge_gens['num_bd_cfi_naive']()) & set(oa_edge_gens['type_cfi']())


def num_id_type_cfi(g, oa_edge_gens, **kwargs):
	"""
	Trivial intersection of num_id_cfi & type_cfi
	"""

	return set(oa_edge_gens['num_id_cfi_naive']()) & set(oa_edge_gens['type_cfi']())


# def ec_cfi(g, indirect_function_callers, indirect_targets, non_trivial_successors, **kwargs):
# 	"""
# 	Split CFG into equivalence classes, i.e., find the minimal labels that work
# 	"""

# 	caller = Object('caller')
# 	callee = Object('callee')
# 	indygraph = nx.DiGraph()
# 	for fc in indirect_function_callers:
# 		for t in non_trivial_successors[fc]:
# 			indygraph.add_edge((fc, caller), (t, callee))
# 	wccs = list(nx.weakly_connected_components(indygraph))
# 	components = []
# 	for wcc in wccs:
# 		callers = set()
# 		callees = set()
# 		for n, t in wcc:
# 			if t == caller:
# 				callers.add(n)
# 			else:
# 				assert t == callee
# 				callees.add(n)
# 		components.append((callers, callees))

# 	g.graph['ec_ec'] = components

# 	ret = set()

# 	for i, (callers, callees) in enumerate(components):
# 		for c in callers:
# 			g.nodes[c]['ec_indirect_caller_ec'] = i + 1
# 		for c in callees:
# 			g.nodes[c]['ec_indirect_callee_ec'] = i + 1
# 		for f in callers:
# 			for t in callees:
# 				ret.add((f, t))
# 	return ret


# def num_ec_cfi(g, **kwargs):
# 	"""
# 	Trivial intersection of num_cfi & ec_cfi
# 	"""

# 	e = set(ec_cfi(g, **kwargs))
# 	n = set(num_cfi(g, **kwargs))

# 	return e & n



def sof_cfi(g, indirect_function_callers, function_addrs, **kwargs):
	"""
	Allow every indirect function call to call any indirect target that is the beginning of a function.
	"""

	ret = []

	for fc in indirect_function_callers:
		ret.append((fc, 'virtualfunction'))
	for pt in function_addrs:
		ret.append(('virtualfunction', pt))

	return ret



def no_cfi(g, target, indirect_function_callers, **kwargs):
	"""
	Allow every indirect function call to call any block.
	As a shortcut, add edges just to target predecessors.
	"""

	ret = []

	for fc in indirect_function_callers:
		ret.append((fc, 'any'))

	for n in g.nodes():
		if n != target:
			ret.append(('any', n))

	# for fc in indirect_function_callers:
	# 	for n in g.nodes():
	# 		if n != target:
	# 			ret.append((fc, n))

	# for fc in indirect_function_callers:
	# 	for n in g.predecessors(target):
	# 		ret.append((fc, n))

	return ret




_oas = namedtuple('_oas', ['fn', 'extra_cmdlineargs'])
__oas = lambda fn, ea=(): _oas(fn, ea)

overapproximation_fns = {oas.fn.__name__: oas for oas in (
	__oas(baseline),
	__oas(num_bd_cfi_naive),
	__oas(num_id_cfi_naive),
	__oas(num_bd_cfi),
	__oas(num_id_cfi),
	__oas(type_cfi, ('dwarf_types_file', 'bin_dir', 'fn_calls', 'map_file')),
	__oas(num_bd_type_cfi, ('dwarf_types_file', 'bin_dir', 'fn_calls', 'map_file')),
	__oas(num_id_type_cfi, ('dwarf_types_file', 'bin_dir', 'fn_calls', 'map_file')),
	__oas(numarg_cfi, ('dwarf_types_file', 'bin_dir', 'fn_calls', 'map_file')),
	__oas(sof_cfi),
	__oas(no_cfi),
)}
































#
