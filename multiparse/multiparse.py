from tqdm import tqdm
from angrmgmt.cfglint import lint_cfg
from angrmgmt.loader import load_angr_proj
from .cfggrind_parser import parse_cfggrind_cfg
from .cfg_merge import InstrManager, FnManager
from common import rjson, wjson, print_state


def multiparse(angr_cfg_fs, mappf, bindir, outf, maX=None):
	print_state('Reading map file')
	mapp = rjson(mappf)

	print_state('Loading binaries into angr')
	proj = load_angr_proj(mapp, bindir)

	print_state('Loading angr CFGs')
	im = InstrManager(proj, mapp['ignored_libs'])
	fm = FnManager()

	for angr_cfg_f in (angr_cfg_fs):
		js = rjson(angr_cfg_f)
		im.add_angr(lint_cfg(js['blocks']))
		fm.add_angr(js['functions'].values())

	print_state('Loading CFGgrind CFGs')
	for i, dirname in enumerate(tqdm(mapp['included_dirs'], desc="Adding CFGgrind runs")):
		nfns, nbbs = parse_cfggrind_cfg(f"{dirname}/cfg.cfg")

		im.add_cfggrind(nbbs)
		fm.add_cfggrind(nfns.values())

		if maX and i >= maX:
			break

	print_state('Generating BBs')
	bbs = im.get_bbs()

	print_state('Writing output file')
	wjson({
		'functions': fm.fns,
		'blocks': bbs
	}, outf)
	print_state('End')


if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(
		description='Combine multiple CFGs',
	)
	parser.add_argument('angr_cfg', help='Files with angr CFGs', type=argparse.FileType('r'), nargs='+')
	parser.add_argument('map', help='Map file', type=argparse.FileType('r'))
	parser.add_argument('binarydir', help='Directory binaries')
	parser.add_argument('output', help='Output JSON file', type=argparse.FileType('w'))
	parser.add_argument('--max', help='Maximum number of CFGgrind files to load', type=int)
	apns = parser.parse_args()

	multiparse(
		angr_cfg_fs=apns.angr_cfg,
		mappf=apns.map,
		bindir=apns.binarydir,
		outf=apns.output,
		maX=apns.max)

#
