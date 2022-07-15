import capstone.x86 as cx86
from common import Hex


def analyze_bb(proj, addr, size):
	bb = proj.factory.block(addr, size)
	lock_insns = set()
	syscall_insns = set()

	binary_basename = proj.loader.find_object_containing(addr).binary_basename

	section = proj.loader.find_section_containing(int(addr))
	in_plt = section.name == '.plt'

	instr_sizes = [i.size for i in bb.capstone.insns]
	if sum(instr_sizes) != bb.size:
		# dissasembly error
		instr_sizes = None
		end_insn_indir = None

	else:
		for ins in bb.capstone.insns:
			if ins.insn.prefix[0] == cx86.X86_PREFIX_LOCK or ins.insn.id == cx86.X86_INS_XCHG:  # xchg has implicit lock
				lock_insns.add(Hex(ins.insn.address))
			if ins.insn.id == cx86.X86_INS_SYSCALL:
				syscall_insns.add(Hex(ins.insn.address))

		li = bb.capstone.insns[-1]
		if {cx86.X86_GRP_JUMP, cx86.X86_GRP_CALL, cx86.X86_GRP_BRANCH_RELATIVE}.intersection(li.insn.groups):  # jump or call or "branch"
			call = cx86.X86_GRP_CALL in li.insn.groups
			jump = not call  # "branch" included here

			assert len(li.insn.operands) == 1
			if li.insn.operands[0].type in {cx86.X86_OP_MEM, cx86.X86_OP_REG}:  # if indirect
				if jump:
					end_insn_indir = 'jump_indirect'
				else:
					end_insn_indir = 'call_indirect'
			else:
				if jump:
					end_insn_indir = 'jump_direct'
				else:
					end_insn_indir = 'call_direct'

		elif cx86.X86_GRP_RET in li.insn.groups:
			end_insn_indir = 'ret'

		elif li.insn.prefix[0] in {cx86.X86_PREFIX_REP, cx86.X86_PREFIX_REPE, cx86.X86_PREFIX_REPNE}:
			end_insn_indir = 'rep'

		elif li.insn.id == cx86.X86_INS_SYSCALL:
			end_insn_indir = 'syscall'

		else:
			end_insn_indir = 'misc'

	return {
		'instr_sizes': instr_sizes,
		'end_insn_indir': end_insn_indir,
		'lock_insns': lock_insns,
		'syscall_insns': syscall_insns,
		'binary_basename': binary_basename,
		'in_plt': in_plt,
	}

#
