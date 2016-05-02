import gdb
import time
import requests as APIRequest
import optparse
import os
import sys
import json as ParseOBJ
from elftools.elf.sections import SymbolTableSection
from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import (
        ifilter, byte2int, bytes2str, itervalues, str2bytes)
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_type, describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
    describe_ver_flags, describe_note
    )

class ReadElf(object):
	def __init__(self, file, output):
		self.elffile = ELFFile(file)
		self.output = output
		self._dwarfinfo = None
		self._versioninfo = None

	def _format_hex(self, addr, fieldsize=None, fullhex=False, lead0x=True,
                    alternate=False):
		if alternate:
			if addr == 0:
				lead0x = False
			else:
				lead0x = True
				fieldsize -= 2

		s = '0x' if lead0x else ''
		if fullhex:
			fieldsize = 8 if self.elffile.elfclass == 32 else 16
		if fieldsize is None:
			field = '%x'
		else:
			field = '%' + '0%sx' % fieldsize
		return s + field % addr



	def display_symbol_tables(self):
		for section in self.elffile.iter_sections():
			if not isinstance(section, SymbolTableSection):
				continue
			if section['sh_entsize'] == 0:
				self._emitline("\nSymbol table '%s' has a sh_entsize of zero!" % (
					bytes2str(section.name)))
			if bytes2str(section.name) == ".symtab":
				print("All defined values of symbol table")
				for nsym, symbol in enumerate(section.iter_symbols()):
					if describe_symbol_type(symbol['st_info']['type']) == "FUNC":
						print(self._format_hex(symbol['st_value'], fullhex=True, lead0x=True)+" "+bytes2str(symbol.name))
		
		        
	def _emitline(self, s=''):
		self.output.write(str(s).rstrip() + '\n')

class openDec(gdb.Command):
	"GDB script for retdec.com"
	def __init__ (self):
		super (openDec,self).__init__ ("dec",gdb.COMMAND_BREAKPOINTS,gdb.COMPLETE_NONE, False)

	def invoke(self, args, from_tty):
		false = True
		self.__key__= "d6585a6b-8dff-4c20-bfac-43938056c27a"
		self.__filename__ = gdb.current_progspace().filename
		params = gdb.string_to_argv(args)

		parser = optparse.OptionParser(usage='dec (sel|arch|end|hhl|key|symbols)\n')
		parser.add_option('-s', '--sel', dest='selective', help='Selective decompile')
		parser.add_option('-a', '--arch', dest='architecture', help='Architecture')
		parser.add_option('-e', '--end', dest='endian', help='Endianness')
		parser.add_option('-l', '--hhl', dest='highl', help='High-level language')
		parser.add_option('-k', '--key', dest='apikey', help='API KEY')
		parser.add_option('-f', '--symbols', dest='symbols', help='List symbols')

		(self.__options__,args) = parser.parse_args(params)

		if(self.__options__.symbols == "all"):
			self.listsym()
		else:
			self.auth()
			self.uploadfile()

	def auth(self):
		self.__options__.apikey = self.__key__ if self.__options__.apikey == None else self.__options__.apikey
		api_key = self.__options__.apikey
		request = APIRequest.Session()
		request.auth = (api_key,'')

		return request

	def dec(self,url):
		request = self.auth()
		resp = request.get(url)
		return resp.content

	def progressbar(self):
		for i in range(21):
		    sys.stdout.write('\r')
		    sys.stdout.write("[%-20s] %d%%" % ('='*i, 5*i))
		    sys.stdout.flush()
		    time.sleep(0.25)
		print("\n")


	def deobj(self,decobj):
		decobj = decobj.decode("utf-8")
		objint = ParseOBJ.loads(decobj)
		if(len(objint)>=3):
			if(objint['code'] == 401):
				print("The API key was not provided or it is invalid.")
				sys.exit()
			elif(objint['code'] >= 400):
				print("A problem occurred on the server.")
				sys.exit()
		return objint['links']['outputs']+'/hll'

	def uploadfile(self):
		request = self.auth()
		files = {'input': open(self.__filename__,'rb')}
		val = {'mode': 'bin','target_language': self.__options__.highl,'sel_decomp_funcs': self.__options__.selective,'architecture': self.__options__.architecture,'raw_endian': self.__options__.endian}
		cont = request.post('https://retdec.com/service/api/decompiler/decompilations',files=files,params=val)
		self.progressbar()
		decobj = self.deobj(cont.content)
		print(self.dec(decobj).decode('utf-8'))
	
	def listsym(self):
		stream=None
		with open(self.__filename__, 'rb') as file:
			readelf = ReadElf(file, stream or sys.stdout)
			readelf.display_symbol_tables()
#
openDec()

