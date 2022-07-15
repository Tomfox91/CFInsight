from collections import defaultdict
from collections.abc import Iterable
from tqdm import tqdm
from .cfggrind_parser import Fn, BB
from common import ensuredkv, print_warning


class InstrManager:
	def __init__(self, angr_proj, ignored_libs):
		self.addrs = defaultdict(dict)
		self.bbcache = {}
		self.angr_proj = angr_proj
		self.ignored_libs = ignored_libs
		for l in self.ignored_libs.values():
			l['start'] = (l['start']) & ~0xfff
			l['end'] = (l['end'] + 0xfff) & ~0xfff
		self.warnings = set()

	# properties:
	# first instruction:
	# 	start
	# 	binary_basename
	# 	fn_addrs
	# 	in_plt
	# 	angr
	# 	cfggrind
	# last instruction:
	# 	end
	# 	end_insn_indir
	# 	out_edges

	def _get_props(self, addr, size):
		from angrmgmt.instr_analyzer import analyze_bb

		if (addr, size) not in self.bbcache:
			try:
				self.bbcache[(addr, size)] = analyze_bb(self.angr_proj, addr, size)
			except KeyError:
				breakpoint()
				pass

		return self.bbcache[(addr, size)]


	def _is_within_ignored_lib(self, addr):
		if addr in {'exit', 'halt'}:
			return False
		assert isinstance(addr, int), breakpoint()
		for l in self.ignored_libs.values():
			if addr >= l['start'] and addr < l['end']:
				return True
		else:
			return False


	def _add_instrs(self, bbs):
		addrs = self.addrs
		for bb in bbs:
			assert isinstance(bb, (dict, BB)), breakpoint()

			if self._is_within_ignored_lib(bb['addr']):
				continue

			props = self._get_props(bb['addr'], bb['size'])

			if props['instr_sizes'] is None:
				props['instr_sizes'] = [bb['size']]
				fake_instr_sizes = True
			else:
				fake_instr_sizes = False

			first_instr = bb['addr']

			instr_end = first_instr
			assert isinstance(props['instr_sizes'], Iterable), breakpoint()
			for instr_size in props['instr_sizes']:
				instr_start = instr_end
				instr_end = instr_start + instr_size

				if instr_start not in addrs:
					addrs[instr_start]['instr_size'] = instr_size
					addrs[instr_start]['fake_instr_sizes'] = fake_instr_sizes
				else:
					assert 'instr_size' in addrs[instr_start], breakpoint()
					assert addrs[instr_start]['instr_size'] == instr_size, breakpoint()
					addrs[instr_start]['fake_instr_sizes'] &= fake_instr_sizes

				if instr_start in props['lock_insns']:
					ensuredkv(addrs[instr_start], 'lock_insn', True)

				if instr_start in props['syscall_insns']:
					ensuredkv(addrs[instr_start], 'syscall_insn', True)

				if not fake_instr_sizes:
					for a in range(instr_start + 1, instr_end):
						assert a not in addrs, breakpoint()

			last_instr = instr_start
			next_bb = last_instr + instr_size

			addrs[first_instr]['start'] = True
			addrs[last_instr]['end'] = True
			addrs[first_instr].setdefault('fn_addrs', set())
			ensuredkv(addrs[first_instr], 'binary_basename', props['binary_basename'])
			ensuredkv(addrs[first_instr], 'in_plt', props['in_plt'])
			addrs[last_instr].setdefault(
				'out_edges',
				defaultdict(lambda: defaultdict(lambda: 0)))
			ensuredkv(addrs[last_instr], 'end_insn_indir', props['end_insn_indir'])
			yield (bb, first_instr, last_instr, props['end_insn_indir'], next_bb)


	def add_angr(self, bbs):
		addrs = self.addrs

		for bb, first_instr, last_instr, end_insn_indir, next_bb in self._add_instrs(tqdm(bbs.values(), desc="Adding angr BBs")):
			addrs[first_instr]['angr'] = True
			addrs[first_instr]['fn_addrs'].update(bb['fn_addrs'])

			# edges
			for n, t in bb['angr_successors']:
				if t == 'Ijk_Call':
					ci = 'call_indirect' if end_insn_indir == 'call_indirect' else 'call_direct'
					addrs[last_instr]['out_edges'][(n, ci)]['angr'] = True

					assert end_insn_indir in {'call_direct', 'call_indirect', None}, breakpoint()
				else:
					assert t in {'Ijk_Boring', 'Ijk_InvalICache'}

					if n == last_instr and end_insn_indir == 'rep':
						addrs[last_instr]['out_edges'][(n, 'jump_direct')]['angr'] = True

					elif n == next_bb:
						addrs[last_instr]['out_edges'][(n, 'follow')]['angr'] = True

					elif end_insn_indir in {'jump_direct', 'jump_indirect', None}:
						ji = 'jump_indirect' if end_insn_indir == 'jump_indirect' else 'jump_direct'
						addrs[last_instr]['out_edges'][(n, ji)]['angr'] = True

					elif addrs[n].get('lock_insn', False):
						pass  # weird angr artifact

					else:
						print_warning(f"{t} edge {first_instr} - {last_instr} -> {n} with end_insn_indir {end_insn_indir}. Skipped.", past_warnings=self.warnings)


	def add_cfggrind(self, bbs):
		addrs = self.addrs

		for bb, first_instr, last_instr, end_insn_indir, next_bb in self._add_instrs(bbs):
			addrs[first_instr]['cfggrind'] = True
			if (bb.is_indirect) != (end_insn_indir in {'call_indirect', 'jump_indirect', None}):
				print_warning(f"block {first_instr} - {last_instr} {'in' if bb.is_indirect else ''}direct BB with end_insn_indir {end_insn_indir}. Skipped.", past_warnings=self.warnings)

			# edges
			for n, num in bb.called_fns_addrs.items():
				if self._is_within_ignored_lib(n):
					continue

				if end_insn_indir in {'call_indirect', 'jump_indirect', 'call_direct', 'jump_direct'}:
					pass
				else:
					print_warning(f"block {first_instr} - {last_instr} fncall -> {n} with end_insn_indir {end_insn_indir}. Adding anyway.", past_warnings=self.warnings)
				addrs[last_instr]['out_edges'][(n, end_insn_indir)]['cfggrind'] += num

			for n, num in bb.succ_bb_addrs.items():
				if self._is_within_ignored_lib(n):
					continue

				if n in {'exit', 'halt'}:
					pass

				elif num == 0:
					pass

				elif n == last_instr and end_insn_indir == 'rep':
					addrs[last_instr]['out_edges'][(n, 'jump_direct')]['cfggrind'] += num

				elif n == next_bb:
					addrs[last_instr]['out_edges'][(n, 'follow')]['cfggrind'] += num

				elif end_insn_indir in {'jump_direct', 'jump_indirect', None}:
					ji = 'jump_indirect' if end_insn_indir == 'jump_indirect' else 'jump_direct'
					addrs[last_instr]['out_edges'][(n, ji)]['cfggrind'] += num

				else:
					addrs[last_instr]['out_edges'][(n, 'unknown')]['cfggrind'] += num
					pass


	def get_bbs(self):
		addrs = self.addrs
		saddrs = sorted(addrs.keys())

		# sanity checks
		assert addrs[saddrs[0]]['start'], breakpoint()

		for i in range(len(saddrs) - 1):
			# handle fake_instr_sizes
			if addrs[saddrs[i]].get('fake_instr_sizes', False):
				addrs[saddrs[i]]['instr_size'] = min(addrs[saddrs[i]]['instr_size'], saddrs[i + 1] - saddrs[i])

			# if bb doesn't end here, the next instruction starts after this
			if not addrs[saddrs[i]].get('end', False):
				assert saddrs[i + 1] == saddrs[i] + addrs[saddrs[i]]['instr_size'], breakpoint()
			# otherwise, it's at least not overlapping
			else:
				assert saddrs[i + 1] >= saddrs[i] + addrs[saddrs[i]]['instr_size'], breakpoint()

		bbs = {}
		bb_start = saddrs[0]
		bb_instr_sizes = []
		for i in range(len(saddrs)):
			bb_instr_sizes.append(addrs[saddrs[i]]['instr_size'])

			# first_instr props
			if addrs[saddrs[i]].get('start', False):
				fn_addrs = addrs[saddrs[i]]['fn_addrs']
				in_plt = addrs[saddrs[i]].get('in_plt', None)
				angr = addrs[saddrs[i]].get('angr', False)
				cfggrind = addrs[saddrs[i]].get('cfggrind', False)
				fake_instr_sizes = addrs[saddrs[i]].get('fake_instr_sizes', False)
				binary_basename = addrs[saddrs[i]].get('binary_basename', False)

			assert angr or cfggrind, breakpoint()

			# decide if this instruction is the last of the BB
			if (
				addrs[saddrs[i]].get('end', False) or
				addrs[saddrs[i]].get('syscall_insn', False) or
				i == len(saddrs) - 1 or
				addrs[saddrs[i + 1]].get('start', False)):
				
				assert bb_start not in bbs
				assert sum(bb_instr_sizes[:-1]) == saddrs[i] - bb_start
				
				bbs[bb_start] = {
					'addr': bb_start,
					'size': sum(bb_instr_sizes),
					'instr_sizes': bb_instr_sizes,
					'fn_addrs': fn_addrs,
					'binary_basename': binary_basename,
					'found_by':
						(['angr'] if angr else []) +
						(['cfggrind'] if cfggrind else [])
				}
				if in_plt is not False:
					bbs[bb_start]['in_plt'] = in_plt
				if fake_instr_sizes:
					bbs[bb_start]['fake_instr_sizes'] = fake_instr_sizes

				# if it is a proper end:
				if addrs[saddrs[i]].get('end', False):
					oe = addrs[saddrs[i]]['out_edges']
					bbs[bb_start]['end_insn_indir'] = addrs[saddrs[i]]['end_insn_indir']
				# otherwise, it is a synthetic split
				else:
					assert 'out_edges' not in addrs[saddrs[i]]
					# if it was split bc of a syscall instruction
					if addrs[saddrs[i]].get('syscall_insn', False):
						bbs[bb_start]['end_insn_indir'] = 'syscall'
					else:
						bbs[bb_start]['end_insn_indir'] = 'follow'
				if not addrs[saddrs[i]].get('end', False) or addrs[saddrs[i]].get('syscall_insn', False):
					neXt = saddrs[i] + addrs[saddrs[i]]['instr_size']
					if neXt in addrs:
						oe = {(neXt, 'follow'): {'split': True}}

				bbs[bb_start]['out_edges'] = []
				for ((target, tYpe), cd) in oe.items():
					bbs[bb_start]['out_edges'].append({
						'to': target,
						'type': tYpe,
						'how': cd,
					})

				bb_start = saddrs[i + 1] if i < len(saddrs) - 1 else None
				bb_instr_sizes = []

		return bbs


class FnManager:
	def __init__(self):
		self.fns = {}

	def add_angr(self, nfns):
		fns = self.fns
		for nfn in nfns:
			if nfn['addr'] not in fns:
				fns[nfn['addr']] = dict(nfn)
				fns[nfn['addr']]['names'] = {nfn['name']}
				del fns[nfn['addr']]['name']

			else:
				assert fns[nfn['addr']]['addr'] == nfn['addr'], breakpoint()
				fns[nfn['addr']]['names'].add(nfn['name'])
				assert fns[nfn['addr']]['binary_name'] == nfn['binary_name'], breakpoint()

	def add_cfggrind(self, nfns):
		fns = self.fns
		for nfn in nfns:
			assert isinstance(nfn, Fn), breakpoint()
			if nfn.addr not in fns:
				fns[nfn.addr] = {
					'addr': nfn.addr,
					'binary_name': nfn.binary_name,
					'names': {nfn.fn_name},
					'invocations': nfn.invocations,
				}
			else:
				assert fns[nfn.addr]['addr'] == nfn.addr, breakpoint()
				fns[nfn.addr]['names'].add(nfn.fn_name)
				assert not nfn.binary_name or fns[nfn.addr]['binary_name'] == nfn.binary_name, breakpoint()
				fns[nfn.addr].setdefault('invocations', 0)
				fns[nfn.addr]['invocations'] += nfn.invocations


#
