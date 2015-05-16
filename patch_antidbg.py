"""
Short script to patch the various functions, locations to avoid Debugger detection.
"""

import immlib

def IsDebuggerPresent_patch(imm):
	"""
	Makes the IsDebuggerPresnt function to always return 0.
	This patch is redundant, because later we set the PEB!IsDebugged field to 0 anyway, which is verified by the IsDebuggerPresent function.
	"""
	isdbg_addr = imm.getAddress("kernel32.IsDebuggerPresent")
	if (isdbg_addr <= 0):
		return False
	imm.log("IsDebuugerPresent found at %s" % hex(isdbg_addr))
	patch = imm.assemble("XOR EAX, EAX\n RET")
	imm.writeMemory(isdbg_addr, patch)
	return True
	
def CheckRemoteDebuggerPresent_patch(imm):
	"""
	Makes the CheckRemoteDebuggerPresent function to always return 0.
	"""
	chkremotedbg_addr = imm.getAddress("kernel32.CheckRemoteDebuggerPresent")
	if (chkremotedbg_addr <= 0):
		return False
	imm.log("CheckRemoteDebuggerPresent found at %s" % hex(chkremotedbg_addr))
	patch = imm.assemble("XOR EAX, EAX\n RET")
	imm.writeMemory(chkremotedbg_addr, patch)
	return True

def OutputDebugStringA_patch(imm):
	"""
	Makes the OutputDebugStringA function to always return 1. (If a debugger is present the return value is the address of the string passed in the argument of the function).
	"""
	outdbgstr_addr = imm.getAddress("kernel32.OutputDebugStringA")
	if (outdbgstr_addr <= 0):
		return False
	imm.log("OutputDebugStringA found at %s" % hex(outdbgstr_addr))
	patch = imm.assemble("MOV EAX, 1\n RET")
	imm.writeMemory(outdbgstr_addr, patch)
	return True

def PEB_IsDebugged_patch(imm):
	"""
	Sets the IsDebugged field in the PEB to 0.
	"""
	imm.writeMemory(imm.getPEBAddress() + 0x2, "\x00" )
	
def PEB_NtGlobalFlags_patch(imm):
	"""
	Sets the NtGlobalFlags field in the PEB to 0.
	If a debugger is present the following flags would be set: FLG_HEAP_ENABLE_TAIL_CHECK, FLG_HEAP_ENABLE_FREE_CHECK and FLG_HEAP_VALIDATE_PARAMETERS and the value of the field would be 0x70.
	"""
	imm.writeMemory(imm.getPEBAddress() + 0x68, "\x00" )
	
def main(args):
	imm = immlib.Debugger()
	if (IsDebuggerPresent_patch(imm)):
		imm.log("IsDebuggerPresent patched")
	else: imm.log("Couldn't find IsDebuggerPresent")
	if (CheckRemoteDebuggerPresent_patch(imm)):
		imm.log("CheckRemoteDebuggerPresent patched")
	else: imm.log("Couldn't find CheckRemoteDebuggerPresent")
	if (OutputDebugStringA_patch(imm)):
		imm.log("OutputDebugStringA patched")
	else: imm.log("Couldn't find OutputDebugStringA")
	PEB_IsDebugged_patch(imm)
	imm.log("PEB_IsDebugged patched")
	PEB_NtGlobalFlags_patch(imm)
	imm.log("PEB_NtGlobalFlags patched")
	return "Done. Check log window for results."
	
	
	