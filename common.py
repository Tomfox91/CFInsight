import datetime
import math
import os.path
import sys
import json


class Hex(int):
	def __new__(self, s):
		if isinstance(s, int):
			return super(Hex, self).__new__(self, s)
		else:
			return super(Hex, self).__new__(self, int(s, 16))

	def __add__(self, other):
		res = super(Hex, self).__add__(other)
		return self.__class__(res)

	def __sub__(self, other):
		res = super(Hex, self).__sub__(other)
		return self.__class__(res)

	def __and__(self, other):
		res = super(Hex, self).__and__(other)
		return self.__class__(res)

	def __or__(self, other):
		res = super(Hex, self).__or__(other)
		return self.__class__(res)



	def __repr__(self):
		return self.print_0x()

	def __str__(self):
		return self.print_0x()

	def print_0x(self):
		return f"0x{self:x}"


class Object:
	def __init__(self, string):
		self.string = string

	def __repr__(self):
		return self.string



def jsonpreprocess(o):
	if isinstance(o, Hex):
		return str(o)
	elif o == math.inf:
		return "Infinity"
	elif isinstance(o, dict):
		return {jsonpreprocess(k): jsonpreprocess(v) for k, v in o.items()}
	elif isinstance(o, (list, set, frozenset, tuple)):
		return [jsonpreprocess(v) for v in o]
	elif hasattr(o.__class__, 'todict') and callable(o.todict):
		return jsonpreprocess(o.todict())
	else:
		return o


def jsonpostprocess(o):
	if isinstance(o, str) and o.startswith('0x'):
		return Hex(o)
	elif isinstance(o, str) and o == 'Infinity':
		return math.inf
	elif isinstance(o, dict):
		return {jsonpostprocess(k): jsonpostprocess(v) for k, v in o.items()}
	elif isinstance(o, list):
		return [jsonpostprocess(v) for v in o]
	else:
		return o


def rjson(f, skip_postprocess=False):
	if isinstance(f, str):
		ff = open(f, 'r')
	else:
		assert hasattr(f, 'read')
		ff = f
	if skip_postprocess:
		ret = json.load(ff)
	else:
		ret = jsonpostprocess(json.load(ff))
	if isinstance(f, str):
		ff.close()
	return ret


def wjson(o, f, skip_preprocess=False):
	if isinstance(f, str):
		ff = open(f, 'w')
	else:
		ff = f
	if skip_preprocess:
		json.dump(o, ff)
	else:
		json.dump(jsonpreprocess(o), ff)
	if isinstance(f, str):
		ff.close()


def ensuredkv(d, k, v):
	assert d.setdefault(k, v) == v, breakpoint()








def format_time():
	now = datetime.datetime.now()
	if "last" in format_time.__dict__:
		diff = now - format_time.last
		format_time.last = now
		return now.strftime('%Y-%m-%d %H:%M:%S.%f') + f" (+{diff.seconds:4}.{diff.microseconds:06}s)"
	else:
		format_time.last = now
		return now.strftime('%Y-%m-%d %H:%M:%S.%f') + " " * 16


_print_state_prefix = []


def print_state_push(*args):
	_print_state_prefix.extend(args)


def print_state_pop():
	_print_state_prefix.pop()


def print_state(*args):
	out = f"\x1b[36m{format_time()}"

	escapes = ["\x1b[31m", "\x1b[33m", "\x1b[35m", "\x1b[32m", "\x1b[94m", "\x1b[36m", "\x1b[37m"]
	for arg in _print_state_prefix + list(args):
		out += f" {escapes.pop(0)}{arg}"
	out += "\x1b(B\x1b[m"
	
	print(out, file=sys.stderr)


def print_warning(text, past_warnings=set()):
	import inspect
	frame = inspect.stack()[1][0]
	info = inspect.getframeinfo(frame)

	if (info.filename, info.lineno, text) in past_warnings:
		pass
	else:
		past_warnings.add((info.filename, info.lineno, text))
		print('\x1b[4;33mWarning\x1b[0;33m: ', end='')
		print(f"\x1b[0;35m{info.filename}:{info.lineno}\x1b[0;33m: ", end='')
		print(text, end='')
		print("\x1b(B\x1b[m")



def ensure_dir(dir):
	os.makedirs(dir, exist_ok=True)


def new_numbered_dir(basedir, prefix=""):
	ensure_dir(basedir)
	i = 0
	prevdir = None
	while True:
		try:
			d = f"{basedir}/{prefix}{i:05}"
			os.mkdir(d)
			return (d, i, prevdir)
		except FileExistsError:
			i += 1
			prevdir = d


class NumberedDir():
	def __init__(self, basedir, prefix=""):
		super().__init__()
		self.basedir = basedir
		self.prefix = prefix

	def __enter__(self):
		self.dir, self.i, self.prevdir = new_numbered_dir(self.basedir, self.prefix)
		return self

	def __exit__(self, *_):
		pass


class SyncedNumberedDir():
	def __init__(self, basedir, prefix=""):
		super().__init__()
		self.basedir = basedir
		self.prefix = prefix

	def __enter__(self):
		self.dir, self.i, self.prevdir = new_numbered_dir(self.basedir, self.prefix)
		if self.i > 0:
			assert os.path.isfile(f"{self.prevdir}/done")
		return self

	def __exit__(self, *_):
		open(f"{self.dir}/done", 'a').close()
		lastdirname = f"{self.basedir}/{self.prefix}last"
		if self.i > 0:
			os.unlink(lastdirname)
		os.symlink(f"{self.prefix}{self.i:05}", lastdirname, target_is_directory=True)



def optintern(s):
	if isinstance(s, str):
		return sys.intern(s)
	else:
		return s


#
