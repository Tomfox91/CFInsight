import re
import subprocess
from collections import namedtuple

symre = re.compile(
	r'(?P<functionname>[^\'\n]+)\n' +
	r'(?P<filename>[^:\n]+):(?P<line>\d+):(?P<column>\d+)\n')

fflc = namedtuple('fflc', ('functionname', 'filename', 'line', 'column'))




class Symbolizer():
	def __init__(self, bindir):
		self.bindir = bindir
		self.procs = {}

	def _getproc(self, binpath, offset):
		if (binpath, offset) in self.procs:
			pass
		else:
			args = ['llvm-symbolizer-11', '--relativenames', f"--obj={binpath}", f"--adjust-vma=0x{offset:x}"]
			print(f"Creating new subprocess for {binpath}, {offset}: {args}")

			self.procs[(binpath, offset)] = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
		return self.procs[(binpath, offset)]

	def __del__(self):
		print("Closing subprocesses")
		for proc in self.procs.values():
			proc.terminate()
			proc.wait()


	def symbolize(self, binpath, addr, offset):
		"""
		Returns a list of frames (>1 in case of inlines).
		The most local call is the first item.
		"""
		binpath = f"{self.bindir}/{binpath}"
		proc = self._getproc(binpath, offset)
		buf = ""
		proc.stdin.write(f"{addr}\n")
		proc.stdin.flush()
		while not buf.endswith('\n\n'):
			buf += proc.stdout.buffer.read1(512).decode()
		return Symbolizer.proc_single_output(buf)


	@staticmethod
	def symbolize_single(binpath, addr, offset):
		import subprocess
		scp = subprocess.run(
			['llvm-symbolizer-11', '--relativenames', f"--obj={binpath}", f"0x{addr:x}", f"--adjust-vma={offset}"],
			check=True, capture_output=True, universal_newlines=True)
		return Symbolizer.proc_single_output(scp.stdout)

	
	@staticmethod
	def proc_single_output(output):
		matches = list(symre.finditer(output))
		assert matches, output

		ret = []

		assert matches[0].span()[0] == 0, breakpoint()
		for i, match in enumerate(matches):
			if i:
				assert matches[i - 1].span()[1] == matches[i].span()[0], breakpoint()
			ret.append(fflc(
				functionname=match.group('functionname'),
				filename=match.group('filename'),
				line=int(match.group('line')),
				column=int(match.group('column'))))
		assert matches[-1].span()[1] == len(output) - 1, breakpoint()
		assert output[-1] == '\n'

		return ret


#
