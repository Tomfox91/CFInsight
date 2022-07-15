import re
from collections import namedtuple, defaultdict
from .symbolizer import Symbolizer

fcre = re.compile(
	r'(?P<filename>[^:]+):' +
	r'((?P<unkline>0)|(?P<line>\d+):(?P<column>\d+))' +
	r'( (?P<inlinedata>@\[.+ \]+))?' +
	r' \'(?P<functionname>[^\']+)\'' +
	r' >(?P<types>[^\']+)<' +
	r' "(?P<ir>.+)"')


class FCR:
	def __init__(self, string):
		match = fcre.fullmatch(string)
		assert match, string

		self.filename = match.group('filename')
		if match.group('unkline'):
			self.line = None
			self.column = None
		else:
			self.line = int(match.group('line'))
			self.column = int(match.group('column'))
		self.inlinedata = match.group('inlinedata')
		self.functionname = match.group('functionname')
		self.types = match.group('types').split(' ')
		for i, t in enumerate(self.types):
			if t == 'long':
				self.types[i] = 'long int'
			elif t == 'Pointer(long)':
				self.types[i] = 'Pointer(long int)'
		self._ir = match.group('ir')

	def __repr__(self):
		return ' '.join(f"{k}: {v}" for k, v in self.__dict__.items() if k[0] != '_' and v is not None)


fcres = namedtuple(
	'fcres', ('addr', 'loc', 'types', 'bindiff', 'functionsmatch'))


class FCManager:
	def __init__(self, dirname, mapp, bindir):
		import pathlib

		self.dirname = dirname
		self.mapp = mapp
		self.compilertypes = defaultdict(lambda: defaultdict(dict))
		self.symbolizer = Symbolizer(bindir)

		for f in pathlib.Path(dirname).iterdir():
			if f.suffix == '.txt':
				pre = ''
				for line in f.read_text().splitlines():
					if line.endswith('"'):
						fcr = FCR(pre + line)
						self.compilertypes[fcr.filename][fcr.line][fcr.column] = fcr
						pre = ''
					else:
						pre += line

	def _get_type(self, binname, addr):
		lib = self.mapp['libs'][binname]

		for bindiff in range(0, -128, -1):
			locs = self.symbolizer.symbolize(lib['bpath'], addr + bindiff, lib['load_offset'])
			assert locs, breakpoint()
			loc = locs[0]
			if loc.filename == '??' or loc.line != 0 or loc.column != 0:
				break

		if loc.filename == '??' or loc.line == 0 or loc.column == 0:
			return fcres(addr, loc, None, None, None)
		try:
			fc = self.compilertypes[loc.filename][loc.line][loc.column]
			return fcres(
				addr=addr, loc=loc, types=fc.types, bindiff=bindiff,
				functionsmatch=any(l.functionname == fc.functionname for l in locs))
		except KeyError:
			return fcres(addr, loc, None, None, None)

	def get_type(self, *args, **kwargs):
		gt = self._get_type(*args, **kwargs)
		if gt.types:
			return tuple(gt.types[1:])  # we ignore the return type
		else:
			return None


if __name__ == '__main__':
	from common import rjson
	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument('fncalls')
	parser.add_argument('cfg_file', type=argparse.FileType('r'))
	parser.add_argument('map_file', type=argparse.FileType('r'))
	parser.add_argument('--only_binary')

	apns = parser.parse_args()

	js = rjson(apns.cfg_file)
	mapp = rjson(apns.map_file)

	fcma = FCManager(apns.fncalls, mapp)

	for bb in js['blocks'].values():
		if apns.only_binary:
			assert bb['binary_basename']
			if bb['binary_basename'] != apns.only_binary:
				continue

		if bb["end_insn_indir"] == "call_indirect":
			assert not bb.get('fake_instr_sizes', False)
			end_insn_addr = bb['addr'] + sum(bb['instr_sizes'][:-1])
			print(fcma.get_type(bb['binary_basename'], end_insn_addr))



#
