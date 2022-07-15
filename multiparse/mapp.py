import re
import glob
import os
import sys
import json
import subprocess
from collections import namedtuple
from common import Hex, jsonpreprocess


class Map():
	@staticmethod
	def _get_text_start(file, dirname):
		filename = f"{dirname}/{file}"
		assert os.path.isfile(filename), f"Missing file: {filename}"
		s = subprocess.run(["/usr/bin/objdump", "-wh", filename, "-j", ".text"], stdout=subprocess.PIPE, check=True)
		ll = s.stdout.decode('ascii').splitlines()[-1].split()
		assert ll[1] == '.text'
		return Hex(ll[3])

	_iMapp = namedtuple('_iMapp', ['bpath', 'start', 'length', 'end'])
	_iMappRes = namedtuple('_iMappRes', ['mapp', 'binname', 'skipped_dirs', 'included_dirs'])

	@staticmethod
	def _read_mapfile(fname):
		ret = set()
		with open(fname, 'r') as inf:
			for line in inf:
				match = re.match(r"(?P<path>.*):(?P<start>0x[0-9a-f]+):(?P<lenght>\d+)", line)
				bpath = match.group('path')
				start = Hex(match.group('start'))
				length = int(match.group('lenght'))
				end = start + length
				bpath = re.sub(r"run/run_base_(test|train)_cl11cfi-m64\.0000", 'run/run_base_refspeed_cl11cfi-m64.0000', bpath)
				assert bpath.startswith('/')
				ret.add(Map._iMapp(bpath, start, length, end))
		return frozenset(ret)

	@staticmethod
	def _read_mapfiles(dirname):
		mapp = None
		binname = None
		skipped_dirs = set()
		skipped_mapps = set()
		included_dirs = set()

		for fname in glob.glob(dirname + '/*/map.map'):
			m = Map._read_mapfile(fname)
			if mapp is None:
				mapp = m
			else:
				if mapp == m:
					pass
					included_dirs.add(os.path.dirname(fname))
				else:
					if m in skipped_mapps:
						skipped_dirs.add(os.path.dirname(fname))
					else:
						print(f"\x1b[33mMap discrepancy\x1b(B\x1b[m")
						print(f"fname: {fname}")
						print(f"Current: {chr(10).join([str(im) for im in mapp])}")
						print(f"+Diff: {m - mapp}")
						print(f"-Diff: {mapp - m}")
						if input('Ignore? ').lower().startswith('y'):
							skipped_dirs.add(os.path.dirname(fname))
							skipped_mapps.add(m)
						else:
							sys.exit(-1)

		for fname in glob.glob(dirname + '/*/run.json'):
			if os.path.dirname(fname) not in skipped_dirs:
				with open(fname, 'r') as inf:
					js = json.load(inf)
					if binname is None:
						binname = js['binname']
					else:
						assert binname == js['binname']
					del js

		return Map._iMappRes(
			mapp=mapp,
			binname=binname,
			skipped_dirs=frozenset(skipped_dirs),
			included_dirs=frozenset(included_dirs))

	def __init__(self, dirname, bindir):
		super().__init__()

		self.main = None
		self.libc = None
		self.libs = {}
		self.ignored_libs = {}
		self.total_exec_size = 0

		mapp, self.binname, self.skipped_dirs, self.included_dirs = \
			Map._read_mapfiles(dirname)

		for bpath, start, length, end in mapp:
			bname = os.path.basename(bpath)

			if 'valgrind' in bpath:
				self.ignored_libs[bname] = {
					'bpath': bpath,
					'start': start,
					'length': length,
					'end': end,
				}

			else:
				load_offset = start - Map._get_text_start(bpath, bindir)
				assert (load_offset & 0xFFF) == 0, f"load_offset = {load_offset}"

				p = {
					'bpath': bpath,
					'start': start,
					'length': length,
					'end': end,
					'load_offset': load_offset
				}

				if bname == self.binname:
					self.main = p
					self.total_exec_size += length
				self.libs[bname] = p
				self.total_exec_size += length
				if bname.startswith('libc-'):
					self.libc = p

		assert self.main is not None, f"binname = {self.binname}"
		if self.libc is None:
			print("Warning: no libc")

	def __repr__(self):
		return f"main: {self.main}, libs: {self.libs}"

	def todict(self):
		return {
			'main': self.main,
			'libc': self.libc,
			'libs': self.libs,
			'ignored_libs': self.ignored_libs,
			'total_exec_size': self.total_exec_size,
			'binname': self.binname,
			'skipped_dirs': self.skipped_dirs,
			'included_dirs': self.included_dirs,
		}


if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(
		description='Analyze CFGgrind mapfiles',
	)
	parser.add_argument('cfggrinddir', help='Directory with subdirs for CFGgrind runs')
	parser.add_argument('binarydir', help='Directory binaries')
	parser.add_argument('output', help='Output JSON file')
	apns = parser.parse_args()

	mapp = Map(apns.cfggrinddir, apns.binarydir)

	with open(apns.output, 'w') as outf:
		json.dump(jsonpreprocess(mapp), outf, indent='\t')
