from collections import defaultdict
from itertools import chain
from common import Hex, rjson





class FunctionTypes():

	@staticmethod
	def allsupertypes_fn(types):
		if not types:
			return {()}
		elif isinstance(types, int):
			return {types}
		else:
			first, rest = types[0], types[1:]

			prest = FunctionTypes.allsupertypes_fn(rest)

			pfirst = {first}
			if first.startswith('Pointer') and first != 'Pointer(void)':
				pfirst.add('Pointer(void)')
			pfirst.add('void')

			ret = set()
			for pf in pfirst:
				for pr in prest:
					ret.add((pf,) + pr)

			if __debug__:
				for ts in ret:
					for t in ts:
						assert isinstance(t, (str, int)), breakpoint()

			return frozenset(ret)


	def functions_with_type(self, types):
		return chain(*(self._functions_with_type[typ] for typ in FunctionTypes.allsupertypes_fn(types)))

	def functions_with_types(self, types):
		return chain(*(self.functions_with_type(typ) for typ in types))


	def __init__(self, dwarftypesf, overrides, functions):
		obj = rjson(dwarftypesf)

		c = 10000

		self._functions_with_type = defaultdict(set)
		self.type_of_function = {}

		for fn in obj:
			a = Hex(fn['addr'])
			ts = fn['return_parameter_types']
			if a not in functions:
				continue
			self.type_of_function[a] = tuple(ts[1:])  # we ignore the return type

		for fn in chain(functions, overrides.values()):
			if fn not in self.type_of_function:
				self.type_of_function[fn] = c
				c += 1

		for fna, target_fn in overrides.items():
			self.type_of_function[fna] = self.type_of_function[target_fn]

		for fna, ts in self.type_of_function.items():
			self._functions_with_type[ts].add(fna)

		print(f"Fake types: {c-10000}, functions with real types: {len(self.type_of_function) - (c-10000)}")





class FunctionNumArg():
	def functions_with_numarg(self, numargs):
		return self._functions_with_numarg[numargs]

	def functions_with_numargs(self, numargs):
		return chain(*(self.functions_with_numarg(na) for na in numargs))


	def __init__(self, dwarftypesf, overrides, functions):
		obj = rjson(dwarftypesf)

		self._functions_with_numarg = defaultdict(set)
		self.numarg_of_function = {}

		for fn in obj:
			a = Hex(fn['addr'])
			na = len(fn['return_parameter_types']) - 1
			if a not in functions:
				continue
			self.numarg_of_function[a] = na

		for fna, target_fn in overrides.items():
			self.numarg_of_function[fna] = self.numarg_of_function.get(target_fn, -1)

		for fna, ts in self.numarg_of_function.items():
			self._functions_with_numarg[ts].add(fna)



if __name__ == '__main__':
	import sys
	q = FunctionTypes(sys.argv[1], {}, ())
	w = FunctionNumArg(sys.argv[1], {}, ())
	breakpoint()
