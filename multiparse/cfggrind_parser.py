import re
from collections import Counter
from common import Hex




cfg_re = re.compile(
	r'\[cfg (?P<addr>0x[0-9a-f]+)' +
	r'(?::(?P<invocations>\d+))?' +
	r' "(?P<cfg_name>[^"]+)"' +
	r' (?P<is_complete>true|false)\]')


class Fn:
	def __init__(self, string):
		match = cfg_re.match(string)
		assert match
		self.addr = Hex(match.group('addr'))
		self.invocations = int(match.group('invocations'))
		cfg_name = match.group('cfg_name')
		if cfg_name == 'unknown':
			self.binary_path = None
			self.binary_name = None
			self.fn_name = None
			self.magic_number = None
		else:
			smatch = re.match(r'(.*)/([^/:]+)::(.*)\((\d+)\)', cfg_name)
			self.binary_path = smatch.group(1)
			self.binary_name = smatch.group(2)
			self.fn_name = smatch.group(3)
			self.magic_number = smatch.group(4)
		self.is_complete = match.group('is_complete') == 'true'
		self.start_bb = None


	def __repr__(self):
		return f"Fn addr: 0x{self.addr:x} invoc: {self.invocations} binary: {self.binary_path}/{self.binary_name} fn_name: {self.fn_name}{' complete' if self.is_complete else ''}"


node_re = re.compile(
	r'\[node (?P<fn_addr>0x[0-9a-f]+)' +
	r' (?P<bb_addr>0x[0-9a-f]+) (?P<bb_size>\d+)' +
	r' \[(?P<instr_sizes>\d+(?: \d+)*)\]' +
	r' \[(?P<called_fns_addrs>(?:0x[0-9a-f]+(?::\d+) ?)*)\]' +
	r' \[(?P<signals>(?:\d+->0x[0-9a-f]+:\d+ ?)*)\]' +
	r' (?P<is_indirect>true|false)' +
	r' \[(?P<succ_bb_addrs>(?:(?:0x[0-9a-f]+|exit|halt)(?::\d+)? ?)*)\]\]')

succ_exit = ('exit')
succ_halt = ('halt')


class BB:
	def __init__(self, string):
		match = node_re.search(string)
		assert match, string
		self.fn_addrs = {Hex(match.group('fn_addr'))}
		self.addr = Hex(match.group('bb_addr'))
		self.size = int(match.group('bb_size'))
		self.instr_sizes = [int(n) for n in match.group('instr_sizes').split()]
		self.instr_num = len(self.instr_sizes)
		assert sum(self.instr_sizes) == self.size
		self.called_fns_addrs = Counter()
		for i in match.group('called_fns_addrs').split():
			if ':' in i:
				a, r = i.split(':')
			else:
				assert False
				a, r = i, 0
			a = Hex(a)
			assert a not in self.called_fns_addrs
			self.called_fns_addrs[a] = int(r)
		self.signals = match.group('signals')  # ignore them for now
		self.is_indirect = match.group('is_indirect') == 'true'
		self.succ_bb_addrs = Counter()
		for i in match.group('succ_bb_addrs').split():
			if ':' in i:
				a, r = i.split(':')
			else:
				a, r = i, 0
			if a == 'exit':
				a = succ_exit
			elif a == 'halt':
				a = succ_halt
			else:
				a = Hex(a)
			assert a not in self.succ_bb_addrs
			self.succ_bb_addrs[a] = int(r)
		# warn if bbs containing a call have extra successors besides next block
		if not self.called_fns_addrs or set(self.succ_bb_addrs.keys()) <= {self.addr + self.size, succ_exit, succ_halt}:
			pass
		else:
			print(f"Warning: function call anomaly: {self}")


	def __repr__(self):
		return f"BB fn_addrs: {self.fn_addrs} addr: {self.addr} size: {self.size} instr_num: {self.instr_num} instr_sizes: {self.instr_sizes}" + (f" called_fns_addrs: {self.called_fns_addrs}" if self.called_fns_addrs else "") + f" {'indirect' if self.is_indirect else 'direct'} succ_bb_addrs: {self.succ_bb_addrs}"

	def __getitem__(self, attr):
		return getattr(self, attr)

	def get(self, attr, default):
		try:
			return getattr(self, attr)
		except AttributeError:
			return default



def parse_cfggrind_cfg(filename):
	fns = {}
	bbs = []

	with open(filename, "r") as cfgfile:
		for l in cfgfile:
			if l[1] == 'c':
				fn = Fn(l)
				assert fn.addr not in fns
				fns[fn.addr] = fn

			elif l[1] == 'n':
				bb = BB(l)
				bbs.append(bb)

			else:
				assert l[0] == '#'

	return fns, bbs


#
