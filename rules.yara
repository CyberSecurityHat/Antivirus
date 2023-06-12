rule PE_file
{
	strings:
		$mz = "MZ"
	condition:
		$mz at 0
}

rule UPX_Packed_PE_file
{
	strings:
		$mz= "MZ"
		$upx= "UPX"
	condition:
		($mz at 0) and $upx
}