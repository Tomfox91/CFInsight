import os
from statistics import mean
import networkx as nx
from common import print_state, Object, rjson, wjson
from .oagraph_eval import generate_graph, wmetricnodes


def fAIR(function_callers, actual_successors, total_exec_size, **_):

	ItR = []
	for caller in function_callers:
		succ = actual_successors[caller]

		if 'any' in succ:
			succnum = total_exec_size
		else:
			succnum = len(succ)
		ItR.append(1. - float(succnum) / float(total_exec_size))

	return mean(ItR)



def fAIA(function_callers, actual_successors, total_exec_size, **_):

	ItC = []
	for caller in function_callers:
		succ = actual_successors[caller]

		if 'any' in succ:
			succnum = total_exec_size
		else:
			succnum = len(succ)
		ItC.append(succnum)

	return mean(ItC)



def iCTR(function_callers, actual_successors, total_exec_size, **_):

	ItC = []
	for caller in function_callers:
		succ = actual_successors[caller]

		if 'any' in succ:
			succnum = total_exec_size
		else:
			succnum = len(succ)
		ItC.append(succnum)

	return sum(ItC)



def QS(g, function_callers, actual_successors, total_exec_size, **_):
	caller = 'caller'
	callee = 'callee'
	indygraph = nx.DiGraph()
	for fc in function_callers:
		for t in g.successors(fc):
			if g.edges[(fc, t)].get('type', None) != 'follow':
				indygraph.add_edge((fc, caller), (t, callee))
	wccs = list(nx.weakly_connected_components(indygraph))
	components = []
	for wcc in wccs:
		callers = set()
		callees = set()
		for n, t in wcc:
			if t == caller:
				callers.add(n)
			else:
				assert t == callee
				callees.add(n)
		components.append((callers, callees))

	maxclasslen = -1
	for callers, callees in components:
		if 'any' in callees:
			maxclasslen = max(maxclasslen, total_exec_size)
			continue
		else:
			classsucc = set()
			for caller in callers:
				classsucc.update(actual_successors[caller])
			maxclasslen = max(maxclasslen, len(classsucc))

	print(f"QS {len(components)} {maxclasslen} {float(len(components)) / maxclasslen}")

	return float(len(components)) / maxclasslen




def compute_other_metrics(oag, mapp):
	oag.remove_node('target')

	actual_successors = {}
	main_bin = os.path.basename(mapp['main']['bpath'])
	indy = [
		n for n in g.nodes
		if g.nodes[n].get('end_insn_indir', None) == 'call_indirect' and
		g.nodes[n].get('binary_basename', None) == main_bin]
	print(f"indy: {len(indy)} nodes")

	for n in indy:
		succ = []
		for s in oag.successors(n):
			if isinstance(s, str):
				if s == 'any':
					succ.append(s)
				else:
					assert s.startswith('virtual')
					succ.extend(oag.successors(s))
			else:
				if oag.edges[(n, s)].get('type', None) != 'follow':
					succ.append(s)
				else:
					pass
		actual_successors[n] = frozenset(succ)

	kwargs = {}
	kwargs['function_callers'] = indy
	kwargs['actual_successors'] = actual_successors
	kwargs['total_exec_size'] = mapp['total_exec_size']

	fret = {}
	for omf in [fAIR, fAIA, iCTR, QS]:
		omn = omf.__name__
		fret[omn] = omf(g=oag, **kwargs)

	loeindy = []
	for n in indy:
		for s in g.successors(n):
			if g.edges[(n, s)].get('type', 'oe') not in {'oe', 'follow'}:
				loeindy.append(n)
				break
	print(f"loeindy: {len(loeindy)} nodes")
	kwargs['function_callers'] = frozenset(loeindy)

	lret = {}
	for omf in [fAIR, fAIA, iCTR, QS]:
		omn = omf.__name__
		lret[omn] = omf(g=oag, **kwargs)

	return {
		'all_blocks': fret,
		'loe_blocks': lret,
		'indy_size': len(indy),
		'loeindy_size': len(loeindy),
	}





if __name__ == '__main__':
	import argparse

	print_state('Init')

	parser = argparse.ArgumentParser(
		description='Evaluate other metrics on a (possibly overapproximated) CFG',
	)
	parser.add_argument('input_cfg', help='Input CFG', type=argparse.FileType('r'))
	parser.add_argument('extra_edges', help='Extra edges', type=argparse.FileType('r'))
	parser.add_argument('map', help='Map file', type=argparse.FileType('r'))
	parser.add_argument("output", help="Output JSON file", type=argparse.FileType('w'))

	apns = parser.parse_args()

	g, fns = generate_graph(apns.input_cfg, apns.extra_edges)
	mapp = rjson(apns.map)

	print_state('Computing other metrics')
	res = compute_other_metrics(g, mapp)

	wjson(res, apns.output)
	print_state('End')






#
