// Huge thank you to FireEye, Crowdstrike, Symantec and Florian Roth for the IOCs

import "pe"

rule APT_Backdoor_MSIL_SUNBURST_1
{
    meta:
        author = "FireEye"
        description = "This rule is looking for portions of the SUNBURST backdoor that are vital to how it functions. The first signature fnv_xor matches a magic byte xor that the sample performs on process, service, and driver names/paths. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $cmd_regex_encoded = "U4qpjjbQtUzUTdONrTY2q42pVapRgooABYxQuIZmtUoA" wide
        $cmd_regex_plain = { 5C 7B 5B 30 2D 39 61 2D 66 2D 5D 7B 33 36 7D 5C 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 33 32 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 31 36 7D }
        $fake_orion_event_encoded = "U3ItS80rCaksSFWyUvIvyszPU9IBAA==" wide
        $fake_orion_event_plain = { 22 45 76 65 6E 74 54 79 70 65 22 3A 22 4F 72 69 6F 6E 22 2C }
        $fake_orion_eventmanager_encoded = "U3ItS80r8UvMTVWyUgKzfRPzEtNTi5R0AA==" wide
        $fake_orion_eventmanager_plain = { 22 45 76 65 6E 74 4E 61 6D 65 22 3A 22 45 76 65 6E 74 4D 61 6E 61 67 65 72 22 2C }
        $fake_orion_message_encoded = "U/JNLS5OTE9VslKqNqhVAgA=" wide
        $fake_orion_message_plain = { 22 4D 65 73 73 61 67 65 22 3A 22 7B 30 7D 22 }
        $fnv_xor = { 67 19 D8 A7 3B 90 AC 5B }
    condition:
        $fnv_xor and ($cmd_regex_encoded or $cmd_regex_plain) or ( ($fake_orion_event_encoded or $fake_orion_event_plain) and ($fake_orion_eventmanager_encoded or $fake_orion_eventmanager_plain) and ($fake_orion_message_encoded and $fake_orion_message_plain) )
}
rule APT_Backdoor_MSIL_SUNBURST_2
{
    meta:
        author = "FireEye"
        description = "The SUNBURST backdoor uses a domain generation algorithm (DGA) as part of C2 communications. This rule is looking for each branch of the code that checks for which HTTP method is being used. This is in one large conjunction, and all branches are then tied together via disjunction. The grouping is intentionally designed so that if any part of the DGA is re-used in another sample, this signature should match that re-used portion. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $a = "0y3Kzy8BAA==" wide
        $aa = "S8vPKynWL89PS9OvNqjVrTYEYqNa3fLUpDSgTLVxrR5IzggA" wide
        $ab = "S8vPKynWL89PS9OvNqjVrTYEYqPaauNaPZCYEQA=" wide
        $ac = "C88sSs1JLS4GAA==" wide
        $ad = "C/UEAA==" wide
        $ae = "C89MSU8tKQYA" wide
        $af = "8wvwBQA=" wide
        $ag = "cyzIz8nJBwA=" wide
        $ah = "c87JL03xzc/LLMkvysxLBwA=" wide
        $ai = "88tPSS0GAA==" wide
        $aj = "C8vPKc1NLQYA" wide
        $ak = "88wrSS1KS0xOLQYA" wide
        $al = "c87PLcjPS80rKQYA" wide
        $am = "Ky7PLNAvLUjRBwA=" wide
        $an = "06vIzQEA" wide
        $b = "0y3NyyxLLSpOzIlPTgQA" wide
        $c = "001OBAA=" wide
        $d = "0y0oysxNLKqMT04EAA==" wide
        $e = "0y3JzE0tLknMLQAA" wide
        $f = "003PyU9KzAEA" wide
        $h = "0y1OTS4tSk1OBAA=" wide
        $i = "K8jO1E8uytGvNqitNqytNqrVA/IA" wide
        $j = "c8rPSQEA" wide
        $k = "c8rPSfEsSczJTAYA" wide
        $l = "c60oKUp0ys9JAQA=" wide
        $m = "c60oKUp0ys9J8SxJzMlMBgA=" wide
        $n = "8yxJzMlMBgA=" wide
        $o = "88lMzygBAA==" wide
        $p = "88lMzyjxLEnMyUwGAA==" wide
        $q = "C0pNL81JLAIA" wide
        $r = "C07NzXTKz0kBAA==" wide
        $s = "C07NzXTKz0nxLEnMyUwGAA==" wide
        $t = "yy9IzStOzCsGAA==" wide
        $u = "y8svyQcA" wide
        $v = "SytKTU3LzysBAA==" wide
        $w = "C84vLUpOdc5PSQ0oygcA" wide
        $x = "C84vLUpODU4tykwLKMoHAA==" wide
        $y = "C84vLUpO9UjMC07MKwYA" wide
        $z = "C84vLUpO9UjMC04tykwDAA==" wide
    condition:
        ($a and $b and $c and $d and $e and $f and $h and $i) or ($j and $k and $l and $m and $n and $o and $p and $q and $r and $s and ($aa or $ab)) or ($t and $u and $v and $w and $x and $y and $z and ($aa or $ab)) or ($ac and $ad and $ae and $af and $ag and $ah and ($am or $an)) or ($ai and $aj and $ak and $al and ($am or $an))
}
rule APT_Backdoor_MSIL_SUNBURST_3
{
    meta:
        author = "FireEye"
        description = "This rule is looking for certain portions of the SUNBURST backdoor that deal with C2 communications. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $sb1 = { 05 14 51 1? 0A 04 28 [2] 00 06 0? [0-16] 03 1F ?? 2E ?? 03 1F ?? 2E ?? 03 1F ?? 2E ?? 03 1F [1-32] 03 0? 05 28 [2] 00 06 0? [0-32] 03 [0-16] 59 45 06 }
        $sb2 = { FE 16 [2] 00 01 6F [2] 00 0A 1? 8D [2] 00 01 [0-32] 1? 1? 7B 9? [0-16] 1? 1? 7D 9? [0-16] 6F [2] 00 0A 28 [2] 00 0A 28 [2] 00 0A [0-32] 02 7B [2] 00 04 1? 6F [2] 00 0A [2-32] 02 7B [2] 00 04 20 [4] 6F [2] 00 0A [0-32] 13 ?? 11 ?? 11 ?? 6E 58 13 ?? 11 ?? 11 ?? 9? 1? [0-32] 60 13 ?? 0? 11 ?? 28 [4] 11 ?? 11 ?? 9? 28 [4] 28 [4-32] 9? 58 [0-32] 6? 5F 13 ?? 02 7B [2] 00 04 1? ?? 1? ?? 6F [2] 00 0A 8D [2] 00 01 }
        $ss1 = "\x00set_UseShellExecute\x00"
        $ss2 = "\x00ProcessStartInfo\x00"
        $ss3 = "\x00GetResponseStream\x00"
        $ss4 = "\x00HttpWebResponse\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Backdoor_MSIL_SUNBURST_4
{
    meta:
        author = "FireEye"
        description = "This rule is looking for specific methods used by the SUNBURST backdoor. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $ss1 = "\x00set_UseShellExecute\x00"
        $ss2 = "\x00ProcessStartInfo\x00"
        $ss3 = "\x00GetResponseStream\x00"
        $ss4 = "\x00HttpWebResponse\x00"
        $ss5 = "\x00ExecuteEngine\x00"
        $ss6 = "\x00ParseServiceResponse\x00"
        $ss7 = "\x00RunTask\x00"
        $ss8 = "\x00CreateUploadRequest\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
rule APT_Dropper_Raw64_TEARDROP_1
{
    meta:
        author = "FireEye"
        description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
    strings:
        $sb1 = { C7 44 24 ?? 80 00 00 00 [0-64] BA 00 00 00 80 [0-32] 48 8D 0D [4-32] FF 15 [4] 48 83 F8 FF [2-64] 41 B8 40 00 00 00 [0-64] FF 15 [4-5] 85 C0 7? ?? 80 3D [4] FF }
        $sb2 = { 80 3D [4] D8 [2-32] 41 B8 04 00 00 00 [0-32] C7 44 24 ?? 4A 46 49 46 [0-32] E8 [4-5] 85 C0 [2-32] C6 05 [4] 6A C6 05 [4] 70 C6 05 [4] 65 C6 05 [4] 67 }
        $sb3 = { BA [4] 48 89 ?? E8 [4] 41 B8 [4] 48 89 ?? 48 89 ?? E8 [4] 85 C0 7? [1-32] 8B 44 24 ?? 48 8B ?? 24 [1-16] 48 01 C8 [0-32] FF D0 }
    condition:
        all of them
}
rule APT_Dropper_Win64_TEARDROP_2
{
    meta:
        author = "FireEye"
        description = "This rule is intended match specific sequences of opcode found within TEARDROP, including those that decode the embedded payload. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
    strings:
        $loc_4218FE24A5 = { 48 89 C8 45 0F B6 4C 0A 30 }
        $loc_4218FE36CA = { 48 C1 E0 04 83 C3 01 48 01 E8 8B 48 28 8B 50 30 44 8B 40 2C 48 01 F1 4C 01 FA }
        $loc_4218FE2747 = { C6 05 ?? ?? ?? ?? 6A C6 05 ?? ?? ?? ?? 70 C6 05 ?? ?? ?? ?? 65 C6 05 ?? ?? ?? ?? 67 }
        $loc_5551D725A0 = { 48 89 C8 45 0F B6 4C 0A 30 48 89 CE 44 89 CF 48 F7 E3 48 C1 EA 05 48 8D 04 92 48 8D 04 42 48 C1 E0 04 48 29 C6 }
        $loc_5551D726F6 = { 53 4F 46 54 57 41 52 45 ?? ?? ?? ?? 66 74 5C 43 ?? ?? ?? ?? 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}


rule APT_SUSP_Solarwinds_Orion_Config_Anomaly_Dec20 {
   meta:
      description = "Detects a suspicious renamed Afind.exe as used by different attackers"
      author = "Florian Roth"
      reference = "https://twitter.com/iisresetme/status/1339546337390587905?s=12"
      date = "2020-12-15"
      score = 70
      nodeepdive = 1
   strings:
      $s1 = "ReportWatcher" fullword wide ascii 

      $fp1 = "ReportStatus" fullword wide ascii
   condition:
      filename == "SolarWindows.Orion.Core.BusinessLayer.dll.config"
      and $s1 
      and not $fp1
}
rule HKTL_NET_GUID_Snaffler {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SnaffCon/Snaffler"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2aa060b4-de88-4d2a-a26a-760c1cefec3e" ascii nocase wide
        $typelibguid1 = "b118802d-2e46-4e41-aac7-9ee890268f8b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShares {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpShares/"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fe9fdde5-3f38-4f14-8c64-c3328c215cf2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
rule Casper_Backdoor_x86 {
 meta:
      description = "Casper French Espionage Malware - Win32/ProxyBot.B - x86 Payload http://goo.gl/VRJNLo"
      author = "Florian Roth"
      reference = "http://goo.gl/VRJNLo"
      date = "2015-03-05"
      modified = "2020-12-18"
      hash = "f4c39eddef1c7d99283c7303c1835e99d8e498b0"
      score = 80
   strings:
      $s1 = "\"svchost.exe\"" fullword wide
      $s2 = "firefox.exe" fullword ascii
      $s3 = "\"Host Process for Windows Services\"" fullword wide
	        $x1 = "\\Users\\*" fullword ascii
      $x2 = "\\Roaming\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
      $x3 = "\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
      $x4 = "\\Documents and Settings\\*" fullword ascii
     $y1 = "%s; %S=%S" fullword wide
      $y2 = "%s; %s=%s" fullword ascii
      $y3 = "Cookie: %s=%s" fullword ascii
      $y4 = "http://%S:%d" fullword wide
     $z1 = "http://google.com/" fullword ascii
      $z2 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" fullword ascii
      $z3 = "Operating System\"" fullword wide
   condition:
      ( filesize < 250KB and all of ($s*) ) or
      ( 3 of ($x*) and 2 of ($y*) and 2 of ($z*) )
}


rule HvS_APT37_smb_scanner {
   meta:
      description = "Unknown smb login scanner used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2020-12-15"
      reference1 = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      reference2 = "https://www.hybrid-analysis.com/sample/d16163526242508d6961f061aaffe3ae5321bd64d8ceb6b2788f1570757595fc?environmentId=2"
   strings:
      $s1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" fullword ascii
      $s2 = "%s - %s:(Username - %s / Password - %s" fullword ascii
      $s3 = "Load mpr.dll Error " fullword ascii
      $s4 = "Load Netapi32.dll Error " fullword ascii
      $s5 = "%s U/P not Correct! - %d" fullword ascii
      $s6 = "GetNetWorkInfo Version 1.0" fullword wide
      $s7 = "Hello World!" fullword wide
      $s8 = "%s Error: %ld" fullword ascii
      $s9 = "%s U/P Correct!" fullword ascii
      $s10 = "%s --------" fullword ascii
      $s11 = "%s%-30s%I64d" fullword ascii
      $s12 = "%s%-30s(DIR)" fullword ascii
      $s13 = "%04d-%02d-%02d %02d:%02d" fullword ascii
      $s14 = "Share:              Local Path:                   Uses:   Descriptor:" fullword ascii
      $s15 = "Share:              Type:                   Remark:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (10 of them)
}

rule HvS_APT37_cred_tool {
   meta:
      description = "Unknown cred tool used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Markus Poelloth"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "Domain Login" fullword ascii
      $s3 = "IEShims_GetOriginatingThreadContext" fullword ascii
      $s4 = " Type Descriptor'" fullword ascii
      $s5 = "User: %s" fullword ascii
      $s6 = "Pass: %s" fullword ascii
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s8 = "E@c:\\u" fullword ascii
   condition:
      filesize < 500KB and 7 of them
}

rule HvS_APT37_RAT_loader {
   meta:
      description = "BLINDINGCAN RAT loader named iconcash.db used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2020-12-15"
      hash = "b70e66d387e42f5f04b69b9eb15306036702ab8a50b16f5403289b5388292db9"
      reference1 = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      reference2 = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-232a"
   condition:
      (pe.version_info["OriginalFilename"] contains "MFC_DLL.dll") and
      (pe.exports("SMain") and pe.exports("SMainW") )
}


rule HvS_APT37_webshell_img_thumbs_asp {
   meta:
      description = "Webshell named img.asp, thumbs.asp or thumb.asp used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "94d2448d3794ae3f29678a7337473d259b5cfd1c7f703fe53ee6c84dd10a48ef"
   strings:
      $s1 = "strMsg = \"E : F\"" fullword ascii
      $s2 = "strMsg = \"S : \" & Len(fileData)" fullword ascii
      $s3 = "Left(workDir, InStrRev(workDir, \"/\")) & \"video\""

      $a1 = "Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $a2 = "Dim tmpPath, workDir" fullword ascii
      $a3 = "Dim objFSO, objTextStream" fullword ascii
      $a4 = "workDir = Request.ServerVariables(\"URL\")" fullword ascii
      $a5 = "InStrRev(workDir, \"/\")" ascii

      $g1 = "WriteFile = 0" fullword ascii
      $g2 = "fileData = Request.Form(\"fp\")" fullword ascii
      $g3 = "fileName = Request.Form(\"fr\")" fullword ascii
      $g4 = "Err.Clear()" fullword ascii
      $g5 = "Option Explicit" fullword ascii
   condition:
      filesize < 2KB and (( 1 of ($s*) ) or (3 of ($a*)) or (5 of ($g*)))
}

rule HvS_APT37_webshell_template_query_asp {
   meta:
      description = "Webshell named template-query.aspimg.asp used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "961a66d01c86fa5982e0538215b17fb9fae2991331dfea812b8c031e2ceb0d90"
   strings:
      $g1 = "server.scripttimeout=600" fullword ascii
      $g2 = "response.buffer=true" fullword ascii
      $g3 = "response.expires=-1" fullword ascii
      $g4 = "session.timeout=600" fullword ascii

      $a1 = "redhat hacker" ascii
      $a2 = "want_pre.asp" ascii
      $a3 = "vgo=\"admin\"" ascii
      $a4 = "ywc=false" ascii

      $s1 = "public  br,ygv,gbc,ydo,yka,wzd,sod,vmd" fullword ascii
   condition:
      filesize > 70KB and filesize < 200KB and (( 1 of ($s*) ) or (2 of ($a*)) or (3 of ($g*)))
}

/* Possibly prone to FPs
rule HvS_APT37_mimikatz_loader_DF012 {
   meta:
      description = "Loader for encrypted Mimikatz variant used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Marc Stroebel"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "42e4a9aeff3744bbbc0e82fd5b93eb9b078460d8f40e0b61b27b699882f521be"
   strings:
      $s1 = ".?AVCEncryption@@" fullword ascii
      $s2 = "afrfa"
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 
      (pe.imphash() == "fa0b87c7e07d21001355caf7b5027219") and (all of them)
}
*/

rule HvS_APT37_webshell_controllers_asp {
   meta:
      description = "Webshell named controllers.asp or inc-basket-offer.asp used by APT37"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Moritz Oettle"
      date = "2020-12-15"
      reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
      hash = "829462fc6d84aae04a962dfc919d0a392265fbf255eab399980d2b021e385517"
   strings:
      $s0 = "<%@Language=VBScript.Encode" ascii
// Case permutations of the word SeRvEr encoded with the Microsoft Script Encoder followed by .scriptrimeOut
      $x1 = { 64 7F 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x2 = { 64 7F 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x3 = { 64 7F 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x4 = { 64 7F 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x5 = { 64 7F 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x6 = { 64 7F 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x7 = { 64 7F 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x8 = { 64 41 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x9 = { 64 41 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x10 = { 64 41 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x11 = { 64 41 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x12 = { 64 7F 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x13 = { 64 41 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x14 = { 64 41 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x15 = { 64 41 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x16 = { 64 41 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x17 = { 64 41 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x18 = { 64 41 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x19 = { 64 41 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x20 = { 64 41 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x21 = { 64 41 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x22 = { 64 41 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x23 = { 64 7F 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x24 = { 64 41 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x25 = { 64 41 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x26 = { 6A 7F 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x27 = { 6A 7F 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x28 = { 6A 7F 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x29 = { 6A 7F 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x30 = { 6A 7F 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x31 = { 6A 7F 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x32 = { 6A 7F 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x33 = { 6A 7F 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x34 = { 64 7F 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x35 = { 6A 7F 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x36 = { 6A 7F 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x37 = { 6A 7F 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x38 = { 6A 7F 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x39 = { 6A 7F 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x40 = { 6A 7F 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x41 = { 6A 7F 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x42 = { 6A 7F 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x43 = { 6A 41 44 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x44 = { 6A 41 44 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x45 = { 64 7F 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x46 = { 6A 41 44 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x47 = { 6A 41 44 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x48 = { 6A 41 44 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x49 = { 6A 41 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x50 = { 6A 41 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x51 = { 6A 41 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x52 = { 6A 41 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x53 = { 6A 41 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x54 = { 6A 41 49 2D 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x55 = { 6A 41 49 2D 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x56 = { 64 7F 44 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x57 = { 6A 41 49 23 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x58 = { 6A 41 49 23 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x59 = { 6A 41 49 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x60 = { 6A 41 49 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x61 = { 64 7F 44 23 41 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x62 = { 64 7F 44 23 41 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x63 = { 64 7F 49 2D 7F 44 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
      $x64 = { 64 7F 49 2D 7F 49 63 2F 6D 4D 6B 61 4F 59 62 3A 6E 72 21 59 }
   condition:
      filesize > 50KB and filesize < 200KB and ( $s0 and 1 of ($x*) )
}
rule LOG_APT_WEBSHELL_Solarwinds_SUNBURST_Report_Webshell_Dec20_2 {
   meta:
      description = "Detects webshell access mentioned in FireEye's SUNBURST report"
      author = "Florian Roth"
      reference = "https://www.guidepointsecurity.com/supernova-solarwinds-net-webshell-analysis/"
      date = "2020-12-21"
   strings:
      $xr1 = /logoimagehandler.ashx[^\n\s]{1,400}clazz=/ ascii wide
   condition:
      $xr1
}
rule COZY_FANCY_BEAR_Hunt {
	meta:
		description = "Detects Cozy Bear / Fancy Bear C2 Server IPs"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
	strings:
		$s1 = "185.100.84.134" ascii wide fullword
		$s2 = "58.49.58.58" ascii wide fullword
		$s3 = "218.1.98.203" ascii wide fullword
		$s4 = "187.33.33.8" ascii wide fullword
		$s5 = "185.86.148.227" ascii wide fullword
		$s6 = "45.32.129.185" ascii wide fullword
		$s7 = "23.227.196.217" ascii wide fullword
	condition:
		uint16(0) == 0x5a4d and 1 of them
}

rule COZY_FANCY_BEAR_pagemgr_Hunt {
	meta:
		description = "Detects a pagemgr.exe as mentioned in the CrowdStrike report"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
	strings:
		$s1 = "pagemgr.exe" wide fullword
	condition:
		uint16(0) == 0x5a4d and 1 of them
}
rule APT_CobaltStrike_Beacon_Indicator {
   meta:
      description = "Detects CobaltStrike beacons"
      author = "JPCERT"
      reference = "https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py"
      date = "2018-11-09"
   strings:
      $v1 = { 73 70 72 6E 67 00 }
      $v2 = { 69 69 69 69 69 69 69 69 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
}
rule CobaltStrike_C2_Host_Indicator {
	meta:
		description = "Detects CobaltStrike C2 host artifacts"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$c2_indicator_fp = "#Host: %s"
		$c2_indicator = "#Host:"
	condition:
		$c2_indicator and not $c2_indicator_fp
		and not uint32(0) == 0x0a786564
		and not uint32(0) == 0x0a796564
}

rule CobaltStrike_Sleep_Decoder_Indicator {
	meta:
		description = "Detects CobaltStrike sleep_mask decoder"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$sleep_decoder = {8B 07 8B 57 04 83 C7 08 85 C0 75 2C}
	condition:
		$sleep_decoder
}

rule CobaltStrike_C2_Encoded_Config_Indicator {
	meta:
		description = "Detects CobaltStrike C2 encoded profile configuration"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$c2_enc_config = {69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 6A 69 6B 69 6D ?? ?? ?? ?? 69 6D 69 6B 69 6D ?? ?? ?? ?? 69 6C 69 68 69 6B ?? ?? 69 6F 69 68 69 6B ?? ?? 69 6E 69 6A 68 69}
	condition:
		$c2_enc_config
}


rule CobaltStrike_C2_Decoded_Config_Indicator {
	meta:
		description = "Detects CobaltStrike C2 decoded profile configuration"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$c2_dec_config = {01 00 00 00 ?? ?? ?? ?? 01 00 00 00 ?? ?? ?? ?? 02 00 00 00 ?? ?? ?? ?? 02 00 00 00 ?? ?? ?? ?? 01 00 00 00 ?? ?? ?? ?? 01 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ??}
	condition:
		$c2_dec_config
}

rule CobaltStrike_Unmodifed_Beacon {
	meta:
		description = "Detects unmodified CobaltStrike beacon DLL"
		author = "yara@s3c.za.net"
		date = "2019-08-16"
	strings:
		$loader_export = "ReflectiveLoader"
		$exportname = "beacon.dll"
	condition:
		all of them
}
rule PUP_ComputraceAgent {
   meta:
      description = "Absolute Computrace Agent Executable"
      author = "ASERT - Arbor Networks (slightly modified by Florian Roth)"
      date = "2018-05-01"
      reference = "https://asert.arbornetworks.com/lojack-becomes-a-double-agent/"
   strings:
      $a = { D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04 }
      $b1 = { 72 70 63 6E 65 74 70 2E 65 78 65 00 72 70 63 6E 65 74 70 00 }
      $b2 = { 54 61 67 49 64 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and ($a or ($b1 and $b2))
}
rule CrowdStrike_SUNSPOT_01 : artifact stellarparticle sunspot {

    meta:
        copyright = "(c) 2021 CrowdStrike Inc."
        description = "Detects RC4 and AES key encryption material in SUNSPOT"

        version = "202101081448"
        last_modified = "2021-01-08"
        actor = "StellarParticle"
        malware_family = "SUNSPOT"

    strings:

        $key = {fc f3 2a 83 e5 f6 d0 24 a6 bf ce 88 30 c2 48 e7}
        $iv  = {81 8c 85 49 b9 00 06 78 0b e9 63 60 26 64 b2 da}

    condition:
        all of them and filesize < 32MB

}

rule CrowdStrike_SUNSPOT_02 : artifact stellarparticle sunspot
{

    meta:
        copyright = "(c) 2021 CrowdStrike Inc."
        description = "Detects mutex names in SUNSPOT"
        version = "202101081448"
        last_modified = "2021-01-08"
        actor = "StellarParticle"
        malware_family = "SUNSPOT"

    strings:
        $mutex_01 = "{12d61a41-4b74-7610-a4d8-3028d2f56395}" wide ascii
        $mutex_02 = "{56331e4d-76a3-0390-a7ee-567adf5836b7}" wide ascii

    condition:
        any of them and filesize < 10MB

}

rule CrowdStrike_SUNSPOT_03 : artifact logging stellarparticle sunspot 

{

    meta:
        copyright = "(c) 2021 CrowdStrike Inc."
        description = "Detects log format lines in SUNSPOT"
        version = "202101081443"
        last_modified = "2021-01-08"
        actor = "StellarParticle"
        malware_family = "SUNSPOT"

    strings:
        $s01 = "[ERROR] ***Step1('%ls','%ls') fails with error %#x***\x0A" ascii
        $s02 = "[ERROR] Step2 fails\x0A" ascii
        $s03 = "[ERROR] Step3 fails\x0A" ascii
        $s04 = "[ERROR] Step4('%ls') fails\x0A" ascii
        $s05 = "[ERROR] Step5('%ls') fails\x0A" ascii
        $s06 = "[ERROR] Step6('%ls') fails\x0A" ascii
        $s07 = "[ERROR] Step7 fails\x0A" ascii
        $s08 = "[ERROR] Step8 fails\x0A" ascii
        $s09 = "[ERROR] Step9('%ls') fails\x0A" ascii
        $s10 = "[ERROR] Step10('%ls','%ls') fails with error %#x\x0A" ascii
        $s11 = "[ERROR] Step11('%ls') fails\x0A" ascii
        $s12 = "[ERROR] Step12('%ls','%ls') fails with error %#x\x0A" ascii
        $s13 = "[ERROR] Step30 fails\x0A" ascii
        $s14 = "[ERROR] Step14 fails with error %#x\x0A" ascii
        $s15 = "[ERROR] Step15 fails\x0A" ascii
        $s16 = "[ERROR] Step16 fails\x0A" ascii
        $s17 = "[%d] Step17 fails with error %#x\x0A" ascii
        $s18 = "[%d] Step18 fails with error %#x\x0A" ascii
        $s19 = "[ERROR] Step19 fails with error %#x\x0A" ascii
        $s20 = "[ERROR] Step20 fails\x0A" ascii
        $s21 = "[ERROR] Step21(%d,%s,%d) fails\x0A" ascii
        $s22 = "[ERROR] Step22 fails with error %#x\x0A" ascii
        $s23 = "[ERROR] Step23 fails with error %#x\x0A" ascii
        $s24 = "[%d] Solution directory: %ls\x0A" ascii
        $s25 = "[%d] %04d-%02d-%02d %02d:%02d:%02d:%03d %ls\x0A" ascii
        $s26 = "[%d] + '%s' " ascii

    condition:
        2 of them and filesize < 10MB
}
rule RaindropPacker
{
    meta:
        copyright = "Symantec"
        family = "Raindrop"

    strings:
        $code = {
            41 8B 4F 20                         //      mov     ecx, [r15+20h]
            49 8D 77 24                         //      lea     rsi, [r15+24h]
            89 8D ?? ?? 00 00                   //      mov     dword ptr [rbp+0A0h+arg_0], ecx
            E8 ?? ?? ?? ??                      //      call    sub_180010270
            33 D2                               //      xor     edx, edx
            48 8D 4C 24 ??                      //      lea     rcx, [rsp+1A0h+var_160]
            44 8D 42 10                         //      lea     r8d, [rdx+10h]
            E8 ?? ?? ?? ??                      //      call    sub_180038610
            48 8D 5C 24 ??                      //      lea     rbx, [rsp+1A0h+var_150]
            F7 DB                               //      neg     ebx
            48 8D 7C 24 ??                      //      lea     rdi, [rsp+1A0h+var_150]
            48 C1 EB 02                         //      shr     rbx, 2
            48 8D 54 24 ??                      //      lea     rdx, [rsp+1A0h+var_160]
            83 E3 03                            //      and     ebx, 3
            48 8D 3C 9F                         //      lea     rdi, [rdi+rbx*4]
            48 8B CF                            //      mov     rcx, rdi
            E8 ?? ?? ?? ??                      //      call    sub_1800101D0
            48 8D 4C 24 ??                      //      lea     rcx, [rsp+1A0h+var_140]
            49 8B D7                            //      mov     rdx, r15
            48 8D 0C 99                         //      lea     rcx, [rcx+rbx*4]
            BB 20 00 00 00                      //      mov     ebx, 20h
            44 8B C3                            //      mov     r8d, ebx
            E8 ?? ?? ?? ??                      //      call    sub_180010ED0
            44 8B 85 ?? ?? 00 00                //      mov     r8d, dword ptr [rbp+0A0h+arg_0]
            48 8B D6                            //      mov     rdx, rsi        ; _QWORD
            49 C1 E8 04                         //      shr     r8, 4           ; _QWORD
            48 8B CF                            //      mov     rcx, rdi        ; _QWORD
            FF 15 ?? ?? ?? ??                   //      call    cs:qword_180056E90
            8B 95 ?? ?? 00 00                   //      mov     edx, dword ptr [rbp+0A0h+arg_0]
            4C 8D 85 ?? ?? 00 00                //      lea     r8, [rbp+0A0h+dwSize]
            48 83 A5 ?? ?? 00 00 00             //      and     [rbp+0A0h+dwSize], 0
            48 8B CE                            //      mov     rcx, rsi
            E8 ?? ?? ?? ??                      //      call    sub_180009630
            48 8B 95 ?? ?? 00 00                //      mov     rdx, [rbp+0A0h+dwSize] ; dwSize
            44 8B CB                            //      mov     r9d, ebx        ; flProtect
            41 B8 00 10 00 00                   //      mov     r8d, 1000h      ; flAllocationType
            33 C9                               //      xor     ecx, ecx        ; lpAddress
            FF 15 ?? ?? ?? ??                   //      call    cs:VirtualAlloc
            48 8B 95 ?? ?? 00 00                //      mov     rdx, [rbp+0A0h+dwSize] ; dwSize
            4C 8D 8D ?? ?? 00 00                //      lea     r9, [rbp+0A0h+flOldProtect] ; lpflOldProtect
            48 8B C8                            //      mov     rcx, rax        ; lpAddress
            41 B8 04 00 00 00                   //      mov     r8d, 4          ; flNewProtect
            48 8B D8                            //      mov     rbx, rax
            FF 15 ?? ?? ?? ??                   //      call    cs:VirtualProtect
            4C 8D 8D ?? ?? 00 00                //      lea     r9, [rbp+0A0h+arg_0]
            4C 8B C6                            //      mov     r8, rsi
            48 8D 95 ?? ?? 00 00                //      lea     rdx, [rbp+0A0h+dwSize]
            48 8B CB                            //      mov     rcx, rbx
            E8 ?? ?? ?? ??                      //      call    sub_1800095A0
            4D 8B C6                            //      mov     r8, r14
            33 D2                               //      xor     edx, edx
            49 8B CF                            //      mov     rcx, r15
            E8 ?? ?? ?? ??                      //      call    sub_180038610
            33 D2                               //      xor     edx, edx        ; dwSize
            41 B8 00 80 00 00                   //      mov     r8d, 8000h      ; dwFreeType
            49 8B CF                            //      mov     rcx, r15        ; lpAddress
            FF 15 ?? ?? ?? ??                   //      call    cs:VirtualFree
            48 8B 95 ?? ?? 00 00                //      mov     rdx, [rbp+0A0h+dwSize]
            48 85 D2                            //      test    rdx, rdx
            74 1B                               //      jz      short l_1
            48 8B CB                            //      mov     rcx, rbx
            80 31 ??                            // l_0: xor     byte ptr [rcx], 39h
            48 FF C1                            //      inc     rcx
            48 8B 95 ?? ?? 00 00                //      mov     rdx, [rbp+0A0h+dwSize] ; dwSize
            48 8B C1                            //      mov     rax, rcx
            48 2B C3                            //      sub     rax, rbx
            48 3B C2                            //      cmp     rax, rdx
            72 E8                               //      jb      short l_0
            44 8B 85 ?? ?? 00 00                // l_1: mov     r8d, [rbp+0A0h+flOldProtect] ; flNewProtect
            4C 8D 8D ?? ?? 00 00                //      lea     r9, [rbp+0A0h+flOldProtect] ; lpflOldProtect
            48 8B CB                            //      mov     rcx, rbx        ; lpAddress
            FF 15 ?? ?? ?? ??                   //      call    cs:VirtualProtect
            FF D3                               //      call    rbx
        }

    condition:
        all of them
}
