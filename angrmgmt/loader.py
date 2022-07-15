import angr
from common import Hex


def load_angr_proj(mapp, bindir, only_main=False, **kwargs):
	main_opts = {'base_addr': mapp['main']['load_offset']} if mapp['main']['load_offset'] else {}

	lib_opts = {}
	for n, l in mapp['libs'].items():
		if l['bpath'] != mapp['main']['bpath']:
			lib_opts[n] = {'base_addr': l['load_offset']}

	angr_args = dict(
		thing=f"{bindir}/{mapp['main']['bpath']}",
		main_opts=main_opts, lib_opts=lib_opts,
		ld_path=(
			f"{bindir}/lib/x86_64-linux-gnu/",
			f"{bindir}/usr/lib/x86_64-linux-gnu/",
			f"{bindir}/usr/lib/llvm-11/lib/",
		),
		use_system_libs=False, except_missing_libs=True, **kwargs)

	if only_main:
		angr_args['auto_load_libs'] = False

	print(angr_args)

	proj = angr.Project(**angr_args)

	main_text = proj.loader.main_object.sections_map['.text']
	assert main_text.min_addr == mapp['main']['start'], f"angr = {main_text.min_addr}, map = {mapp['main']['start']}"
	assert main_text.filesize == mapp['main']['length'], f"angr = {main_text.filesize}, map = {mapp['main']['length']}"
	if not only_main:
		for n, l in mapp['libs'].items():
			lib_text = proj.loader.find_object(n).sections_map['.text']
			assert lib_text.min_addr == l['start'], f"lib = {n}, angr = {Hex(lib_text.min_addr)}, map = {l['start']}"
			assert lib_text.filesize == l['length'], f"Library length disagreement: lib = {n}, angr = {Hex(lib_text.filesize)}, map = {Hex(l['length'])}"

	return proj


if __name__ == '__main__':
	import argparse
	from common import rjson

	parser = argparse.ArgumentParser(
		description='Load angr project',
	)
	parser.add_argument('map_file', help='Map file', type=argparse.FileType('r'))
	parser.add_argument('binarydir', help='Directory with binaries')
	parser.add_argument('--only_main', help='Only load main binary', action='store_true')

	apns = parser.parse_args()

	mapp = rjson(apns.map_file)
	proj = load_angr_proj(mapp, apns.binarydir, apns.only_main)
#
