rule infostealer_malware 
{
	meta:
	auther="mowath al zobaidi and abd elrahman tawafsheh"
	malware_auther = "dr haith al aani"
	description="this malware steale private ip and devcie name from the computer and send it through the network to example.com "

	strings: 
		
		$ws1 = "http://www.example.com/post_handler" ascii wide 
		$ws2 = "POST" ascii wide 
		$ws3 = "text=" ascii wide 
		$s1 = "CaesarCipher"
		$s2 = "updator.exe" ascii wide 
		$s3= "Hacked.txt" ascii wide 
 		$mz = { 4D 5A }
	condition: 
		($s1 and $s2 and  $s3) or ($ws3 and $ws2 and $ws1) and $mz

}