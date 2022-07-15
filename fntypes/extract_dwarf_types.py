import os.path
from elftools.elf.elffile import ELFFile
from tqdm import tqdm
from common import rjson, wjson, print_state


class NotFound(Exception):
	pass


def find_subprograms(dies):
	queue = list(dies)

	while queue:
		die = queue.pop()

		if die.tag == 'DW_TAG_subprogram':
			yield die

		for child in die.iter_children():
			queue.append(child)


def get_return_argument_types(subprog_die):
	if 'DW_AT_type' in subprog_die.attributes:
		yield subprog_die.get_DIE_from_attribute('DW_AT_type')
	else:
		yield 'void'

	for c in subprog_die.iter_children():
		if c.tag == 'DW_TAG_formal_parameter':
			try:
				yield c.get_DIE_from_attribute('DW_AT_type')
			except KeyError:
				yield c.get_DIE_from_attribute('DW_AT_abstract_origin').get_DIE_from_attribute('DW_AT_type')


def get_typeclass(formparam_die):
	if formparam_die == 'void':
		return 'void'
	elif formparam_die.attributes == {}:
		return 'void'
	elif formparam_die.tag == 'DW_TAG_typedef':
		if 'DW_AT_type' in formparam_die.attributes:
			return get_typeclass(formparam_die.get_DIE_from_attribute('DW_AT_type'))
		else:
			return 'void'
	elif formparam_die.tag in {'DW_TAG_enumeration_type', 'DW_TAG_const_type', 'DW_TAG_restrict_type', 'DW_TAG_volatile_type', 'DW_TAG_rvalue_reference_type'}:
		return get_typeclass(formparam_die.get_DIE_from_attribute('DW_AT_type'))
	elif formparam_die.tag == 'DW_TAG_reference_type':
		return f"Reference({get_typeclass(formparam_die.get_DIE_from_attribute('DW_AT_type'))})"
	elif formparam_die.tag == 'DW_TAG_pointer_type' or formparam_die.tag == 'DW_TAG_ptr_to_member_type':
		if 'DW_AT_type' in formparam_die.attributes:
			return f"Pointer({get_typeclass(formparam_die.get_DIE_from_attribute('DW_AT_type'))})"
		elif 'DW_AT_byte_size' in formparam_die.attributes:
			if formparam_die.attributes['DW_AT_byte_size'].value == 8:
				return f"Pointer(long int)"
			else:
				breakpoint()
		else:
			breakpoint()
	elif formparam_die.tag == 'DW_TAG_array_type':
		return f"Array({get_typeclass(formparam_die.get_DIE_from_attribute('DW_AT_type'))})"
	elif formparam_die.tag == 'DW_TAG_structure_type' or formparam_die.tag == 'DW_TAG_class_type':
		return "struct"
	elif formparam_die.tag == 'DW_TAG_union_type':
		return "union"
	elif formparam_die.tag == 'DW_TAG_subroutine_type':
		return "function"
	elif formparam_die.tag == 'DW_TAG_base_type':
		return formparam_die.attributes['DW_AT_name'].value.decode().replace('unsigned ', '')
	else:
		breakpoint()


def get_name(subprog_die):
	if 'DW_AT_linkage_name' in subprog_die.attributes:
		return subprog_die.attributes['DW_AT_linkage_name'].value.decode()
	elif 'DW_AT_name' in subprog_die.attributes:
		return subprog_die.attributes['DW_AT_name'].value.decode()
	
	elif 'DW_AT_abstract_origin' in subprog_die.attributes:
		return get_name(subprog_die.get_DIE_from_attribute('DW_AT_abstract_origin'))

	elif 'DW_AT_specification' in subprog_die.attributes:
		return get_name(subprog_die.get_DIE_from_attribute('DW_AT_specification'))

	else:
		breakpoint()


def get_addr(subprog_die, name, symtab):
	try:
		return subprog_die.attributes['DW_AT_low_pc'].value
	except KeyError:
		candidates = symtab.get_symbol_by_name(name)
		if candidates and len(candidates) == 1:
			return candidates[0].entry['st_value']
		else:
			raise NotFound


def get_type(subprog_die, symtab, addr_offset):
	if 'DW_AT_inline' in subprog_die.attributes and subprog_die.attributes['DW_AT_inline'].value in (0x01, 0x03):  # DWARF5 spec, page 233 and 82
		return None

	if subprog_die.attributes == {}:
		return None

	name = get_name(subprog_die)
	try:
		addr = get_addr(subprog_die, name, symtab) + addr_offset
	except NotFound:
		return None


	return {
		'name': name,
		'addr': f"0x{addr:x}",
		'return_parameter_types':
			[get_typeclass(p) for p in get_return_argument_types(subprog_die)],
	}




def get_types_from_file(fname, addr_offset):
	fname = os.path.relpath(os.path.realpath(fname))
	fbase = os.path.basename(fname)
	print_state('Parsing file', fname)
	f = open(fname, 'rb')
	elf = ELFFile(f)
	buildid = next(elf.get_section_by_name('.note.gnu.build-id').iter_notes())['n_desc']
	debugf = f"/usr/lib/debug/.build-id/{buildid[:2]}/{buildid[2:]}.debug"

	if os.path.isfile(debugf):
		print(f"Debug symbols for {fbase} found: {debugf}")
		f.close()
		f = open(debugf, 'rb')
		elf = ELFFile(f)

	assert elf.has_dwarf_info()
	dwarf = elf.get_dwarf_info()
	symtab = elf.get_section_by_name('.symtab')

	subprograms = find_subprograms(cu.get_top_DIE() for cu in dwarf.iter_CUs())

	i = 0
	j = 0

	ret = {}
	for sp in tqdm(subprograms, desc='Subprograms'):
		j += 1
		data = get_type(sp, symtab, addr_offset)
		if data:
			data['binary'] = fname
			ret[data['addr']] = data
			i += 1

	f.close()

	print(f"Found data for {i} out of {j} subprograms.")

	return ret



if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(
		description='Extract DWARF type information from binaries',
	)
	parser.add_argument('map', help='Map file', type=argparse.FileType('r'))
	parser.add_argument('binarydir', help='Base directory of binaries')
	parser.add_argument('output', help='Output JSON file', type=argparse.FileType('w'))
	apns = parser.parse_args()

	mapdict = rjson(apns.map)

	ret = {}

	for binary in mapdict['libs'].values():
		offset = binary['load_offset']
		bname = f"{apns.binarydir}/{binary['bpath']}"
		for addr, data in get_types_from_file(bname, offset).items():
			assert addr not in ret, breakpoint()
			ret[addr] = data
	print_state('Done')

	wjson(list(ret.values()), apns.output)


#
