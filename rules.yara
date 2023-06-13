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
		$upx0= "UPX0"
		$upx1= "UPX1"
	condition:
		$mz at 0 and ($upx and $upx0 and $upx1)
}

rule png_file_with_corrupted_signature
{
	strings:
		$header_signature = { 89 50 4E 47 0D 0A 1A 0A }
		$footer_signature = { 49 45 4E 44 AE 42 60 82 }
	condition:
		$header_signature and !$footer_signature at filesize - 8
}

rule jpeg_file_with_corrupted_signature
{
	strings:
		$header_signature1 = { FF D8 FF E0 }
        	$header_signature2 = { FF D8 FF E0 }
		$footer_signature = { FF D9 }
	condition:
		($header_signature1 or $header_signature2)  and !footer_signature at filesize - 2
}

rule gif_file_with_corrupted_signature
{
	strings:
		$header_signature1 = { 47 49 46 38 37 61 }
        	$header_signature2 = { 47 49 46 38 39 61 }
		$footer_signature = { 00 3B }
	condition:
		($header_signature1 or $header_signature2)  and !footer_signature at filesize - 2
}

rule zip_file_with_corrupted_signature
{
	strings:
		$header_signature = { 50 4B 03 04 }
		$footer_signature = { 50 4B 05 06 }
	condition:
		$header_signature  and !footer_signature at filesize - 4
}
