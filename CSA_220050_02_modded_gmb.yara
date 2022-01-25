import pe32

rule CrowdStrike_CSA_220050_02_modded_gmb : commodity loader netdis modded GMB
{
	meta:
		copyright = "(c) 2022 CrowdStrike Inc."
		description = "Characteristic .NET IL bytecode patterns in NetDis second-stage component"
		reports = "CSA-220050"
    		modified_by = "GlennHD"
		version = "202201211003"
		last_modified = "2022-01-21"
		malware_family = "NetDis"

	strings:
		$ = { 20 01 00 01 00 6a 28 }
		$ = { 0a 06 17 58 0a 11 04 06 1f 0a fe 04 60 2c }
		$ = { 7a 08 06 59 0d 07 06 0e 04 0e 05 09 28 }
		$ = { 0a 03 8e 69 06 8e 69 58 8d }
		$ = { 0b 03 16 07 16 03 8e 69 28 }
		$ = { 06 16 07 03 8e 69 06 8e 69 28 }
		$ = { 17 07 73 }

	condition:
		all of them
}
