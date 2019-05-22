#!/usr/bin/env python3

"""
  
Copyright (C) 2019 medsgerj. All rights reserved.

This program is free software; you can redistribute it and/or modify it 
under the terms of the GNU General Public License as published by the Free 
Software Foundation; either version 2 of the License, or (at your option) 
any later version.

This program is distributed in the hope that it will be useful, but WITHOUT 
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with 
this program; if not, write to the Free Software Foundation, Inc., 59 Temple 
Place, Suite 330, Boston, MA 02111-1307 USA

"""

import sys
import os
import optparse
import codecs
import json
import re
import io

CHECK_SIGNATURE_NOT_FOUND = 0
CHECK_SIGNATURE_FOUND = 1
MAX_FILE_SIZE_BYTES = 128 * (2**20)

class LanguageSignatureType:

	def __init__(self, title):
		self.title = title

class LanguageSignatureTypes:

	EXT = LanguageSignatureType(
		title = "Extension"
	)

	CONTENT = LanguageSignatureType(
		title = "Content"
	)

	def all():
		return [
			LanguageSignatureTypes.EXT,
			LanguageSignatureTypes.CONTENT
		]

class Language:

	def __init__(self, title):
		self.title = title

class Languages:

	C = Language(
		title = "C"
	)

	PYTHON = Language(
		title = "Python"
	)

	CPP = Language(
		title = "C++"
	)

	PHP = Language(
		title = "PHP"
	)

	PERL = Language(
		title = "Perl"
	)

	BASH = Language(
		title = "Bash"
	)

	SH = Language(
		title = "Shell"
	)

	GO = Language(
		title = "Go"
	)

	JAVA = Language(
		title = "Java"
	)

	def all():
		return [
			Languages.C,
			Languages.PYTHON,
			Languages.CPP,
			Languages.PHP,
			Languages.PERL,
			Languages.BASH,
			Languages.SH,
			Languages.GO,
			Languages.JAVA
		]

class LanguageSignature:

	def __init__(self, language, signature_type, data):
		self.language = language
		self.signature_type = signature_type
		self.data = data

language_signatures = [

	LanguageSignature( 
		Languages.C,      
		LanguageSignatureTypes.EXT,
		".c"
	),
	LanguageSignature( 
		Languages.PYTHON, 
		LanguageSignatureTypes.EXT, 
		".py"
	),
	LanguageSignature( 
		Languages.CPP,
		LanguageSignatureTypes.EXT,
	  	".cpp"
	),
	LanguageSignature( 
		Languages.CPP,
		LanguageSignatureTypes.EXT,
		".cc"
	),
	LanguageSignature( 
		Languages.PHP,
		LanguageSignatureTypes.EXT,
		".php"
	),
	LanguageSignature( 
		Languages.PERL,
		LanguageSignatureTypes.EXT,
		".pl"
	),
	LanguageSignature( 
		Languages.PERL,
		LanguageSignatureTypes.EXT,
		".pm"
	),
	LanguageSignature( 
		Languages.GO,
		LanguageSignatureTypes.EXT,
		".go"
	),
	LanguageSignature( 
		Languages.PERL,
		LanguageSignatureTypes.CONTENT,
		"#!/usr/bin/perl"
	),
	LanguageSignature( 
		Languages.BASH,
		LanguageSignatureTypes.CONTENT,
		"#!/bin/bash"
	),
	LanguageSignature( 
		Languages.SH,
		LanguageSignatureTypes.CONTENT,
		"#!/bin/sh"
	),
	LanguageSignature(
		Languages.JAVA,
		LanguageSignatureTypes.EXT,
		".java"
	)

]

class CheckConfidence:

	def __init__(self, title):
		self.title = title

class CheckConfidences:

	INFO = CheckConfidence(
		title = "Informational"
	)

	LOW = CheckConfidence(
		title = "Low"
	)

	MEDIUM = CheckConfidence(
		title = "Medium"
	)

	HIGH = CheckConfidence(
		title = "High"
	)

	def all():
		return [
			CheckConfidences.INFO,
			CheckConfidences.LOW,
			CheckConfidences.MEDIUM,
			CheckConfidences.HIGH
		]

class CheckSignatureType:
	
	def __init__(self, title):
		self.title = title

class CheckSignatureTypes:

	TEXT = CheckSignatureType(
		title = "Text"
	)

	REGEX = CheckSignatureType(
		title = "Regex"
	)

	CODE = CheckSignatureType(
		title = "Code"
	)

	def all():
		return [
			CheckSignatureTypes.TEXT,
			CheckSignatureTypes.REGEX,
			CheckSignatureTypes.CODE
		]

class CheckType:

	def __init__(self, title):
		self.title = title

class CheckTypes:

	OSCI = CheckType(
		title = "OS Command Injection"
	)
	
	BUFFER_OVERFLOW = CheckType(
		title = "Buffer Overflow"
	)

	TYPE_CONFUSION = CheckType(
		title = "Type Confusion"
	)

	FILE_INCLUSION = CheckType(
		title = "File Inclusion"
	)

	SQL_INJECTION = CheckType(
		title = "SQL Injection"
	)

	CODE_EVALUATION = CheckType(
		title = "Code Evaluation"
	)

	XXE = CheckType(
		title =  "XML External Entity"
	)

	INSECURE_TMP_FILE = CheckType(
		title = "Insecure Temporary File"
	)

	WILDCARD_INJECTION = CheckType(
		title = "Wildcard Injection"
	)

	INSECURE_FILE_PERMISSIONS = CheckType(
		title = "Insecure File Permissions"
	)

	TOCTOU = CheckType(
		title = "Time of Check to Time of Use"
	)

	def all():
		return [
			CheckTypes.OSCI,
			CheckTypes.BUFFER_OVERFLOW,
			CheckTypes.TYPE_CONFUSION,
			CheckTypes.FILE_INCLUSION,
			CheckTypes.SQL_INJECTION,
			CheckTypes.CODE_EVALUATION,
			CheckTypes.XXE,
			CheckTypes.INSECURE_TMP_FILE,
			CheckTypes.WILDCARD_INJECTION,
			CheckTypes.INSECURE_FILE_PERMISSIONS,
			CheckTypes.TOCTOU
		]

class Check:

	def __init__(
		self, 
		languages = None, 
		check_type = None, 
		check_confidence = None, 
		check_signature_type = None, 
		check_signature_data = None, 
	):
		
		self.languages = languages
		self.check_type = check_type
		self.check_confidence = check_confidence
		self.check_signature_type = check_signature_type
		self.check_signature_data = check_signature_data

checks = [

	Check( 
		[
			Languages.C, 
			Languages.CPP, 
			Languages.PHP
		],
		CheckTypes.OSCI,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		(
			"^(.*=\s*|\s*)"
			"("
			"exec(l|lp|le|v|vpe)*"
			"|"
			"system"
			"|"
			"popen"
			")"
			"\s*\(.+\).*"
		)
	),
	Check( 
		[
			Languages.C, 
			Languages.CPP, 
			Languages.PHP
		],
		CheckTypes.OSCI,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		(
			"^(.*=\s*|\s*)"
			"("
			"exec(l|lp|le|v|vpe)*"
			"|"
			"system"
			"|"
			"popen"
			")"
			"\s*\(.+\).*"
		)
	),
	Check(
		[
			Languages.PHP, 
		],
		CheckTypes.OSCI,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		(
			"^(.*=\s*|\s*)"
			"(passthru|shell_exec|proc_open|pcntl_exec)"
			"\s*\(.+\).*"
		)
	),
	Check( 
		[
			Languages.PERL, 
		],
		CheckTypes.OSCI,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		(
			"^(.*=\s*|\s*)"
			"(exec|system)"
			"\s*(\(|\"|')"
			".+"
			"(\(|\"|')"
			".*"
		)
	),
	Check(
		[
			Languages.PYTHON, 
		],
		CheckTypes.OSCI,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		(
			"^(.*=\s*|\s*)"
			"("
			"(subprocess.)*(call|run|check_output|Popen)"
			"|"
			"(os.)*(system|popen)"
			")"
			"\s*\(.+\).*"
		)
	),
	Check(
		[
			Languages.GO, 
		],
		CheckTypes.OSCI,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		"^(.*=\s*|\s*)exec.Command\s*\(.+\).*"
	),
	Check(
		[
			Languages.C,
			Languages.CPP 
		],
		CheckTypes.BUFFER_OVERFLOW,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		"\s*strcpy\(.+\).*" 
	),
	Check(
		[
			Languages.C,
			Languages.CPP 
		],
		CheckTypes.BUFFER_OVERFLOW,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		"\s*strcat\(.+\).*" 
	),
	Check(
		[
			Languages.C,
			Languages.CPP 
		],
		CheckTypes.BUFFER_OVERFLOW,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		"\s*gets\(.+\).*" 
	),
	Check(
		[
			Languages.C,
			Languages.CPP 
		],
		CheckTypes.BUFFER_OVERFLOW,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		"\s*sprintf\(.+\).*" 
	),
	Check(
		[
			Languages.CPP, 
		],
		CheckTypes.TYPE_CONFUSION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*static_cast.*"
	),
	Check(
		[
			Languages.PHP
		],
		CheckTypes.FILE_INCLUSION,
		CheckConfidences.INFO,	
		CheckSignatureTypes.REGEX,
		"^(.*=\s*|\s*)include(_once)*\(.+\).*"
	),
	Check(
		[
			Languages.PHP
		],
		CheckTypes.FILE_INCLUSION,
		CheckConfidences.INFO,	
		CheckSignatureTypes.REGEX,
		"^(.*=\s*|\s*)require(_once)*\(.+\).*"
	),
	Check( 
		[
			Languages.PHP
		],
		CheckTypes.SQL_INJECTION,
		CheckConfidences.INFO,	
		CheckSignatureTypes.REGEX,
		"^(.*=\s*|\s*)mysql(i)*_query\s*\(.+\).*"
	),
	Check( 
		[
			Languages.PYTHON
		],
		CheckTypes.SQL_INJECTION,
		CheckConfidences.INFO,	
		CheckSignatureTypes.REGEX,
		"^(.*=\s*|\s*)execute\s*\(.+\).*"
	),
	Check( 
		[
			Languages.GO
		],
		CheckTypes.SQL_INJECTION,
		CheckConfidences.INFO,	
		CheckSignatureTypes.REGEX,
		"^(.*=\s*|\s*)db.Exec\s*\(.+\).*"
	),
	Check(
		[
			Languages.PHP
		],
		CheckTypes.CODE_EVALUATION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		"^(.*=\s*|\s*)preg_replace\(.+\).*"
	),
	Check(
		[
			Languages.PHP
		],
		CheckTypes.CODE_EVALUATION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		"^(.*=\s*|\s*)eval\(.+\).*"
	),
	Check(
		[
			Languages.PYTHON
		],
		CheckTypes.CODE_EVALUATION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		"^(.*=\s*|\s*)loads\(.+\).*"
	),
	Check(
		[
			Languages.PYTHON
		],
		CheckTypes.CODE_EVALUATION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		"^(.*=\s*|\s*)input\(.+\).*"
	),
	Check(
		[
			Languages.C,
			Languages.CPP
		],
		CheckTypes.XXE,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*XML_PARSE_NOENT.*"
	),
	Check(
		[
			Languages.C,
			Languages.CPP
		],
		CheckTypes.XXE,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*XML_PARSE_DTDLOAD.*"
	),
	Check( 
		Languages.all(),
		CheckTypes.WILDCARD_INJECTION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*(chown|chown|rm|tar)\s+.*\*.*"
	),
	Check(
		Languages.all(), 
		CheckTypes.INSECURE_TMP_FILE,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*\/tmp\/.*"
	),
	Check( 
		Languages.all(),
		CheckTypes.WILDCARD_INJECTION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*tar\s+\w+\s+\w*\*.*"
	),
	Check( 
		Languages.all(),
		CheckTypes.WILDCARD_INJECTION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*rm\s+.*\*.*"
	),
	Check(
		Languages.all(), 
		CheckTypes.WILDCARD_INJECTION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*rsync\s+.*\*\s+.*"
	),
	Check(
		Languages.all(), 
		CheckTypes.WILDCARD_INJECTION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*chmod\s+.*\*.*"
	),
	Check(
		Languages.all(),
		CheckTypes.WILDCARD_INJECTION,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*chown\s+.*\*.*"
	),
	Check(
		Languages.all(),
		CheckTypes.INSECURE_FILE_PERMISSIONS,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		".*chmod\s*777.*"
	),
	Check(
		[
			Languages.C,
			Languages.CPP
		],
		CheckTypes.TOCTOU,
		CheckConfidences.INFO,
		CheckSignatureTypes.REGEX,
		"^([^\(]*\(\s*|.*=\s*|\s*)access\s*\(.+\).*"
	)

]

def check_signature_cmp(data, check):

	if check.check_signature_type == CheckSignatureTypes.REGEX:

		p = re.compile(check.check_signature_data)
		m = p.match(data)

		if m:
			return CHECK_SIGNATURE_FOUND

	return CHECK_SIGNATURE_NOT_FOUND

def check_get_result_obj(file_path, lang_type, line_count, check, line):

	obj = {}
	obj['file_path'] = file_path.decode(
		"utf-8", 
		"ignore"
	)
	obj['lang'] = lang_type.title
	obj['line_num'] = line_count
	obj['check_confidence'] = check.check_confidence.title
	obj['check_type_title'] = check.check_type.title
	obj['check_signature_data'] = check.check_signature_data
	obj['line'] = line

	return obj

def check_exec(checks, results, file_path, data, lang_type):

	for check in checks:

		if lang_type in check.languages:

			line_count = 1
			lines = data.splitlines()
			for line in lines:

				b = check_signature_cmp(line, check)

				if b == CHECK_SIGNATURE_FOUND:
			
					obj = check_get_result_obj(
						file_path,
						lang_type,
						line_count,
						check,
						line
					)

					results.append(obj)	
				
				line_count += 1
	return 0

def lang_get(file_data, file_path):

	for language_signature in language_signatures:

		signature_language = language_signature.language
		signature_type = language_signature.signature_type
		signature_data = language_signature.data

		if signature_type == LanguageSignatureTypes.EXT:

			file_name, ext = os.path.splitext(file_path)
		
			if signature_data == ext:
				return signature_language
		
		if signature_type == LanguageSignatureTypes.CONTENT:
			
			file_data_len_bytes = len(file_data)
			max_search_len_bytes = 0

			if file_data_len_bytes < 64:
				max_search_len_bytes = file_data_len_bytes
			else:
				max_search_len_bytes = 64

			if signature_data in file_data[0:max_search_len_bytes]:
				return signature_language    

	return None

def process_file(checks_effective, results, file_path):

	ret = os.path.isfile(file_path)

	if ret == False:
		return -1

	file_size_bytes = os.path.getsize(file_path)

	if file_size_bytes > MAX_FILE_SIZE_BYTES: 
		return -1

	fp = codecs.open(
		file_path, 
		"r", 
		encoding="utf-8", 
		errors="ignore"
	)

	file_data = fp.read()	

	lang_x = lang_get(file_data, file_path)

	if lang_x == None:
		fp.close()
		return -1
	
	check_exec(
		checks_effective, 
		results, 
		file_path, 
		file_data, 
		lang_x
	)

	fp.close()	

	return 0

def print_checks():

	checks_len = len(checks)

	for i in range(0, checks_len):

		languages_str = ""
		for language in checks[i].languages:
			languages_str += " " + language.title

		print(
			i,
			languages_str,
			checks[i].check_type.title,
			checks[i].check_signature_data
		)

	return 0

def main():

	results = []

	parser = optparse.OptionParser(
		usage="find [PATH] | python3 %prog [OPTION]",
		version="%prog 0.0.1"
	)

	parser.add_option(
		"-l", 
		"--list-checks", 
		action="store_true",
		dest="list_checks", 
		help="list supported checks"
	)

	parser.add_option(
		"-c",
		"--check",
		type="int",
		dest="check_id",
		help="Check id"
	)

	options, args = parser.parse_args()

	if options.list_checks == True:
		print_checks()
		sys.exit(0)

	checks_effective = checks

	if options.check_id != None:

		if options.check_id >= 0 and options.check_id < len(checks):
			checks_effective = [checks[options.check_id]]
		else:
			sys.stderr.write("Check id out of bounds.\n")
			sys.exit(-1)

	stdin_fp = open(sys.stdin.fileno(), "rb")

	for file_path in stdin_fp:
		file_path = file_path.rstrip()
		process_file(checks_effective, results, file_path)
	
	print(json.dumps(results))

if __name__ == "__main__":
	main()

