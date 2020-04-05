###############################################################################
# Name   : find_element_obj.py v1.2                                           #
# Author : Matteo "uf0" Malvica - www.malvi.ca 2020      					  #  
# Original by: Peter "corelanc0d3r" Van Eeckhoute - www.corelan.be (c) 2013   #                                    
# Descr. : This script will list all objects, sizes,  heap (default/isolated) #
# Req.  :  IDA Pro & IDAPython  (tested on IDA 7.0.1 both x86 and x64)        #
###############################################################################

import os, sys, struct
from idaapi import *
from idc import *
import re

global functionname
global address_list
functionname = "HeapAlloc"	
# Most (if not all) mshtml objects are allocated through HeapAlloc
# via IAT __imp__HeapAlloc

def process_iat_callback(ea, name, ord):
	template = "{0:12} | {1:85} | {2:24} | {3:24} "
	if name:
		thisname = name.lower()
		if (thisname == functionname) or (thisname == functionname+"a") or (thisname == functionname+"w"):
			print "Processing references to %s (0x%08x)" % (name,ea)
			print template.format("Address","Element object","Size","Heap")
			print template.format("-------","--------------","----","----")
			# get all code references to this IAT entry
			for xref in XrefsTo(ea, 0):
				cref = xref.frm
				funcname = idaapi.get_func_name(cref)
				for nref in XrefsTo(cref,0):
					coderef = nref.frm + 6
					if not coderef in address_list:
						address_list.append(coderef)
						# Read disassembly back up to 30 bytes, until we reach dwBytes
						funcname = idaapi.get_func_name(coderef)
						if not funcname == None:
							#if "button" in funcname.lower():
							#	debug = True
							#	print(funcname)
							readback = 1
							size = ""
							theHeap = ""
							thefuncname = ""
							founddwBytes = False
							foundHeap = False
							while readback < 40:
								instr = idc.GetDisasm(coderef-readback)
								#if debug:
								#	print(instr)
								disable_mask = GetLongPrm(INF_SHORT_DN) 
								thefuncname = Demangle(funcname, disable_mask)	
								# x86 block				
								if instr.startswith("push") and "Heap" in instr and not foundHeap:
									allparts = instr.split(" ")
									if len(allparts) > 1:
										theHeap = allparts[-2]
										if len(theHeap) < 5:
											theHeap = allparts[-3]
										theHeap = theHeap.strip(";")
										foundHeap = True
								if instr.startswith("push") and "dwBytes" in instr and not founddwBytes:
									allparts = instr.split(';')
									size = allparts[0].replace("push","").replace(" ","")	
									if "h" in size:
										objsize = size[:-1]
									else:
										objsize = size
									founddwBytes = True
								# x64 block
								if instr.startswith("mov     rcx") and "Heap" in instr and not foundHeap:
									allparts = instr.split(" ")
									if len(allparts) > 1:
										theHeap = allparts[-2]
										if len(theHeap) < 5:
											theHeap = allparts[-3]
										theHeap = theHeap.strip(";")
										foundHeap = True
								if instr.startswith("lea     r8") and "dwBytes" in instr and not founddwBytes:
									allparts = instr.split(';')
									size = allparts[0].replace("lea","").replace(" ","").replace("[","")
									if "h" in size:
										objsize = size[:-1]
									else:
										objsize = size
									founddwBytes = True
								readback += 1
								if founddwBytes and foundHeap:
									break		
							if founddwBytes and foundHeap:
								if not thefuncname == None:
									if "heap" in theHeap.lower():
										print template.format("%s" % hex(coderef), "%s" % thefuncname[0:85], "0x%s bytes" % objsize, "%s" % theHeap)
	return True

def main():
	global functionname
	global address_list
	address_list = []
	functionname = functionname.lower()
	nr_of_imports = idaapi.get_import_module_qty()
	if (nr_of_imports > 0):
		for i in xrange(0,nr_of_imports):
			module_name = idaapi.get_import_module_name(i)
			if not module_name:
				print "[!] Unable to get import module name for index %d" % i
				continue
			idaapi.enum_import_names(i,process_iat_callback)
	else:
		Warning("No imports found")
	print "(+) Done"
	
if __name__ == "__main__":
	main()
