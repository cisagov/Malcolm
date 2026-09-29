import "magic"
import "pe"

// Archive Files

rule _7zip_file {
    meta:
        type = "archive"
    strings:
        $a = { 37 7A BC AF 27 1C }
    condition:
        $a at 0
}

rule arj_file {
    meta:
        type = "archive"
    condition:
        uint16(0) == 0xEA60
}

rule browser_manifest
{
    meta:
        type = "browser manifest"
    strings:
        $ = "manifest_version"
        $ = "name"
        $ = "version"
    condition:
        uint8be(0) == 0x7b and
        filesize < 25KB and
        all of them
}

rule bits_file
{
    meta:
        type = "BITSAdmin DB File"
    strings:
        $a = { B6 BC 93 04 EF CD AB 89 }
    condition:
        $a at 0
}

rule cab_file {
    meta:
        type = "archive"
    strings:
        $a = { 4D 53 43 46 00 00 00 00 }
    condition:
        $a at 0 or
        ( uint16(0) == 0x5A4D and $a )
}

rule cpio_file {
    meta:
        type = "archive"
    strings:
        $a = { 30 37 30 37 30 31 }
    condition:
        $a at 0
}

rule dmg_disk_image {
    meta:
        type = "archive"
    strings:
        $koly = { 6B 6F 6C 79 }  // koly
    condition:
        $koly at filesize - 0x200
}

rule dmg_encrypted_disk_image {
    meta:
        type = "archive"
    strings:
        $v1 = { 65 6E 63 72 63 64 73 61 00 } // encrcdsa - v1
        $v2 = { 63 64 73 61 65 6E 63 72 00 } // cdsaencr - v2
    condition:
        $v1 at 0 or $v2 at 0
}

rule encrypted_zip
{
    meta:
        author = "thudak@korelogic.com"
        comment = "Solution 7 - encrypted zip file"

    strings:
        $local_file = { 50 4b 03 04 }

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $local_file and
        // go through each local file header and see if the encrypt bits are set
        for any i in (1..#local_file): (uint16(@local_file[i]+6) & 0x1 == 0x1)
}

rule encrypted_word_document
{
    meta:
        author = "Derek Thomas"
    strings:
        $ = "EncryptionInfo" wide
        $ = "Microsoft.Container.EncryptionTransform" wide
        $ = "StrongEncryptionDataSpace" wide
        $ = "StrongEncryptionTransform" wide
    condition:
        uint32be(0) == 0xd0cf11e0 and
        any of them
}

rule hfsplus_disk_image {
    meta:
        type = "archive"
        reference = "https://developer.apple.com/library/archive/technotes/tn/tn1150.html"
        reference = "https://fossies.org/linux/file/magic/Magdir/macintosh"
    strings:
        $a = { 48 2B 00 04 }  // H+   Non-bootable
        $b = { 48 2B 4C 78 }  // H+Lx Bootable
    condition:
        $a at 0x400 or
        $b at 0x408
}

rule iso_file {
    meta:
        type = "archive"
    strings:
        $a = { 43 44 30 30 31 }
    condition:
        $a at 0x8001 and $a at 0x8801 and $a at 0x9001
}

rule mhtml_file {
    meta:
        type = "archive"
    strings:
        $a = "MIME-Version: 1.0"
        $b = "This document is a Single File Web Page, also known as a Web Archive file"
    condition:
        $a at 0 and $b
}

rule rar_file {
    meta:
        type = "archive"
    condition:
        uint16(0) == 0x6152 and uint8(2) == 0x72 and uint16(3) == 0x1A21 and uint8(5) == 0x07
}

rule tar_file {
    meta:
        type = "archive"
    strings:
        $a = { 75 73 74 61 72 }
    condition:
        uint16(0) == 0x9D1F or
        uint16(0) == 0xA01F or
        $a at 257
}

rule udf_file {
    meta:
        type = "archive"
    strings:
        $cd_def_1 = "CD001"
        $cd_def_2 = "BEA01"
        $udf_def_1 = "NSR0"
        $udf_def_2 = "BEA01"
        $udf_def_3 = "NSR02"
        $udf_def_4 = "NSR03"
        $udf_def_5 = "TEA01"
    condition:
        for any of ($cd_def_*) : ( $ at 32769 )
            and
        for any of ($udf_def_*) : ( $ in (34817..filesize) )
}

rule vhd_file {
    meta:
        type = "archive"
    strings:
        $a = { 63 6F 6E 65 63 74 69 78 }
    condition:
        $a at 0 or $a at filesize-512
}

rule vhdx_file {
    meta:
        type = "archive"
    strings:
        $a = { 76 68 64 78 66 69 6C 65 }
    condition:
        $a at 0
}

rule xar_file {
    meta:
        type = "archive"
    condition:
        uint32(0) == 0x21726178
}

rule zip_file {
    meta:
        type = "archive"
    condition:
        ( uint32(0) == 0x04034B50 and not uint32(4) == 0x00060014 )
}

// Audio Files

rule mp3_file {
    meta:
        type = "audio"
    condition:
        uint16(0) == 0x4449 and uint8(2) == 0x33
}

// Captures

rule pcap_file {
    meta:
        type = "capture"
    strings:
        $a = { A1 B2 C3 D4 }
        $b = { D4 C3 B2 A1 }
    condition:
        $a at 0 or $b at 0
}

rule pcapng_file {
    meta:
        type = "capture"
    strings:
        $a = { 0A 0D 0D 0A }
        $b = { 1A 2B 3C 4D }
        $c = { 4D 3C 2B 1A }
    condition:
        $a at 0 and ($b at 8 or $c at 8)
}

// Certificate Files

rule pkcs7_file {
    meta:
        type = "certificate"
    strings:
        $a = "-----BEGIN PKCS7-----"
    condition:
        (uint16(0) == 0x8230 and uint16(4) == 0x0906) or
        uint32(0) == 0x09068030 or
        $a at 0
}

rule x509_der_file {
    meta:
        type = "certificate"
    condition:
        uint16(0) == 0x8230 and ( uint16(4) == 0x8230 or uint16(4) == 0x8130 )
}

rule x509_pem_file {
    meta:
        type = "certificate"
    strings:
        $a = "-----BEGIN CERTI"
    condition:
        $a at 0
}

// Compressed Files

rule bzip2_file {
    meta:
        type = "compressed"
    condition:
        uint16(0) == 0x5A42 and uint8(2) == 0x68
}

rule gzip_file {
    meta:
        type = "compressed"
    condition:
        uint16(0) == 0x8B1F and uint8(2) == 0x08
}

rule lzma_file {
    meta:
        type = "compressed"
    condition:
        uint16(0) == 0x005D and uint8(2) == 0x00
}

rule xz_file {
    meta:
        type = "compressed"
    condition:
        uint32(0) == 0x587A37FD and uint16(4) == 0x005A
}

rule zlib_file {
    meta:
        type = "compressed"
    condition:
        uint16(0) == 0x0178 or
        uint16(0) == 0x9C78 or
        uint16(0) == 0xDA78
}

// Document Files

rule doc_subheader_file {
    meta:
        type = "document"
    condition:
        uint32(0) == 0x00C1A5EC
}

rule excel4_file
{
    meta:
        type = "excel4"
    strings:
        $excel4 = { 45 78 63 65 6c (20 34 | 34) } // Excel4 or Excel 4
        $rels = /xl\/_rels\/workbook\.(xml|bin)\.rels/
        $sheet = "xl/macrosheets"
        $xlsstr = "xl/sharedStrings"
    condition:
        (uint32be(0) == 0xd0cf11e0 and $excel4) or
        (uint32be(0) == 0x504b0304 and $rels and $sheet and $xlsstr)
}

rule iqy_file
{
   meta:
      description = "Detects potential IQY (Excel Web Query) files with various protocols"
      author = "Paul Hutelmyer"
      date = "2023-11-02"
   strings:
      $iqy_header = /^WEB(\r\n|\n)/ nocase
      $http = /http:\/\// nocase
      $https = /https:\/\// nocase
      $ftp = /ftp:\/\// nocase
      $ftps = /ftps:\/\// nocase
      $file = /file:\/\// nocase
      $smb = /smb:\/\// nocase
condition:
    $iqy_header at 0 and ($http or $https or $ftp or $ftps or $file or $smb)
}

rule onenote_file
{
    meta:
        type = "document"
    strings:
        $guid = { e4 52 5c 7b 8c d8 a7 4d ae b1 53 78 d0 29 96 d3 }
    condition:
        $guid at 0
}

rule mso_file {
    meta:
        type = "document"
    strings:
        $a = { 3C 3F 6D 73 6F 2D 61 70 70 6C 69 63 61 74 69 6F 6E 20 } // <?mso-application
        $b = { 3C 3F 6D 73 6F 2D 63 6F 6E 74 65 6E 74 54 79 70 65 } // <?mso-contentType
    condition:
        $a at 0 or
        $b at 0
}

rule olecf_file {
    meta:
        description = "Object Linking and Embedding (OLE) Compound File (CF)"
        type = "document"
    condition:
        uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1
}

rule ooxml_file {
    meta:
        description = "Microsoft Office Open XML Format"
        type  = "document"
    condition:
        uint32(0) == 0x04034B50 and uint32(4) == 0x00060014
}

rule pdf_file {
    meta:
        description = "Portable Document Format"
        type = "document"
    condition:
        uint32(0) == 0x46445025
}

rule poi_hpbf_file {
    meta:
        description = "https://poi.apache.org/components/hpbf/file-format.html"
        type = "document"
    strings:
        $a = { 43 48 4E 4B 49 4E 4B } // CHNKINK
    condition:
        $a at 0
}

rule rtf_file {
    meta:
        type = "document"
    condition:
        uint32(0) == 0x74725C7B
}

rule vbframe_file {
    meta:
        type = "document"
    strings:
        $a = { 56 45 52 53 49 4F 4E 20 35 2E 30 30 0D 0A 42 65 67 69 6E } // VERSION 5.00\r\nBegin
    condition:
        $a at 0
}

rule wordml_file {
    meta:
        description = "Microsoft Office Word 2003 XML format"
        type = "document"
    strings:
       $a = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D } // <?xml version=
       $b = "http://schemas.microsoft.com/office/word/2003/wordml"
    condition:
        $a at 0 and $b
}

rule xfdf_file {
    meta:
        description = "XML Forms Data Format"
        type = "document"
    strings:
        $a = { 3C 78 66 64 66 20 78 6D 6C 6E 73 3D } // <xfdf xmlns=
    condition:
        $a at 0
}

// Email Files

rule email_file {
    meta:
        type = "email"
    strings:
        $a = "\x0aReceived:" nocase fullword
        $b = "\x0AReturn-Path:" nocase fullword
        $c = "\x0aMessage-ID:" nocase fullword
        $d = "\x0aReply-To:" nocase fullword
        $e = "\x0aX-Mailer:" nocase fullword
    condition:
        $a in (0..2048) or
        $b in (0..2048) or
        $c in (0..2048) or
        $d in (0..2048) or
        $e in (0..2048)
}

rule email_file_broad
{
    meta:
        type = "email"
    strings:
        $ = "Received: "
        $ = "Origin-messageId: "
        $ = "Return-Path: "
        $ = "From: "
        $ = "To: "
        $ = "Subject: "
        $ = "Date: "
    condition:
        magic.mime_type() == "message/rfc822" or
        all of them
}

rule tnef_file {
    meta:
        description = "Transport Neutral Encapsulation Format"
        type = "email"
    condition:
        uint32(0) == 0x223E9F78
}

// Encoded Files

rule base64_pe {
    meta:
		description = "Detects base64 encoded executable"
    strings:
        $s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" wide ascii
        $s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" wide ascii
        $s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" wide ascii
        $s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" wide ascii
        $s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii
    condition:
        not uint16(0) == 0x5a4d and
        any of them
}

// Encryption Files

rule pgp_file {
    meta:
        type = "encryption"
    strings:
        $a = { ?? ?? 2D 2D 2D 42 45 47 49 4E 20 50 47 50 20 50 55 42 4C 49 43 20 4B 45 59 20 42 4C 4F 43 4B 2D } // (.{2})(\x2D\x2D\x2DBEGIN PGP PUBLIC KEY BLOCK\x2D)
        $b = { ?? ?? 2D 2D 2D 42 45 47 49 4E 20 50 47 50 20 53 49 47 4E 41 54 55 52 45 2D } // (\x2D\x2D\x2D\x2D\x2DBEGIN PGP SIGNATURE\x2D)
        $c = { ?? ?? 2D 2D 2D 42 45 47 49 4E 20 50 47 50 20 4D 45 53 53 41 47 45 2D } // (\x2D\x2D\x2D\x2D\x2DBEGIN PGP MESSAGE\x2D)
        $d = { ?? ?? 2D 2D 2D 42 45 47 49 4e 20 50 47 50 20 53 49 47 4e 45 44 20 4d 45 53 53 41 47 45 2D } // (\x2D\x2D\x2D\x2D\x2DBEGIN PGP SIGNED MESSAGE\x2D)
    condition:
        $a at 0 or
        $b at 0 or
        $c at 0 or
        $d at 0
}

// Executable Files

rule elf_file {
    meta:
        description = "Executable and Linkable Format"
        type = "executable"
    condition:
        uint32(0) == 0x464C457F
}

rule lnk_file {
    meta:
        description = "Windows Shortcut file"
        type = "executable"
    strings:
        $a = { 4c 00 00 00 01 14 02 00 } // Header length + partial CLSID
    condition:
        $a at 0
}

rule macho_file {
    meta:
        description = "Mach object"
        type = "executable"
    condition:
        uint32(0) == 0xCEFAEDFE or
        uint32(0) == 0xCFFAEDFE or
        uint32(0) == 0xFEEDFACE or
        uint32(0) == 0xFEEDFACF
}

rule mz_file {
    meta:
        description = "DOS MZ executable"
        type = "executable"
    condition:
        uint16(0) == 0x5A4D
}

// Image Files

rule bmp_file {
    meta:
        type = "image"
    strings:
        $a = { 42 4D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ( 0C | 28 | 40 | 6C | 7C | 80 ) 00 } // BM
    condition:
        $a at 0
}

rule cmap_file {
    meta:
        type = "image"
    strings:
        $a = { 62 65 67 69 6E 63 6D 61 70 } // begincmap
    condition:
        $a at 0
}

rule gif_file {
    meta:
        description = "Graphics Interchange Format"
        type = "image"
    condition:
        uint32(0) == 0x38464947 and ( uint16(4) == 0x6137 or uint16(4) == 0x6139 )
}

rule jpeg_file {
    meta:
        type = "image"
    condition:
        uint32(0) == 0xE0FFD8FF or
        uint32(0) == 0xE1FFD8FF or
        uint32(0) == 0xE2FFD8FF or
        uint32(0) == 0xE8FFD8FF
}

rule postscript_file {
    meta:
        type = "image"
    strings:
        $a = { 25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 } // %!PS-Adobe-3.0
    condition:
        $a at 0
}

rule png_file {
    meta:
        type = "image"
    condition:
        uint32(0) == 0x474E5089
}

rule psd_file {
    meta:
        description = "Photoshop Document"
        type = "image"
    condition:
        uint32(0) == 0x53504238
}

rule psd_image_file {
    meta:
        description = "Photoshop Document image resource block"
        type = "image"
    condition:
        uint32(0) == 0x4D494238
}

rule svg_file {
    meta:
        type = "image"
    strings:
        $a = { 3C 73 76 67 20 } // <svg
    condition:
        $a at 0
}

rule xicc_file {
    meta:
        type = "image"
    strings:
        $a = { 58 49 43 43 5F 50 52 4F 46 49 4C 45 } // XICC_PROFILE
    condition:
        $a at 0
}

rule xmp_file {
    meta:
        type = "image"
    strings:
        $a = { 3C 3F 78 70 61 63 6B 65 74 20 62 65 67 69 6E 3D } // <?xpacket begin=
        $b = { 3C 78 3A 78 6D 70 6D 65 74 61 20 78 6D 6C 6E 73 3A 78 3D } // <x:xmpmeta xmlns:x=
    condition:
        $a at 0 or $b at 0
}

// Metadata Files

rule jar_manifest_file {
    meta:
        type = "metadata"
    condition:
        uint32(0) == 0x696E614D and uint32(4) == 0x74736566
}

rule bplist_file {
    meta:
        description = "Binary Property List"
        type = "metadata"
    condition:
        uint32(0) == 0x696C7062 and uint32(4) == 0x30307473
}

// Multimedia Files

rule fws_file {
    meta:
        type =  "multimedia"
    condition:
        uint16(0) == 0x5746 and uint8(2) == 0x53
}

rule cws_file {
    meta:
        description = "zlib compressed Flash file"
        type = "multimedia"
    condition:
        uint16(0) == 0x5743 and uint8(2) == 0x53
}


rule zws_file {
    meta:
        description = "LZMA compressed Flash file"
        type =  "multimedia"
    condition:
        uint16(0) == 0x575A and uint8(2) == 0x53
}

// Package Files

rule debian_package_file {
    meta:
        type = "package"
    strings:
        $a = { 21 3C 61 72 63 68 3E 0A 64 65 62 69 61 6E } // \x21\x3Carch\x3E\x0Adebian
    condition:
        $a at 0
}

rule rpm_file {
    meta:
        type = "package"
    condition:
        uint32(0) == 0x6D707264 or uint32(0) == 0xDBEEABED
}

// Packer / Loader Files

rule hacktool_win_shellcode_donut
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcodes"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/"

    strings:
        $loader_ver_1_0_0_V1_x64_raw = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 41 56 41 57 48 81 ec 00 05 00 00 33 ff 48 8b d9 39 b9 38 02 00 00 0f 84 ce 00 00 00 4c 8b 41 28}
        $loader_ver_1_0_0_V1_x64_b64 = "\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x41\x56\x41\x57\x48\x81\xec\x00\x05\x00\x00\x33\xff\x48\x8b\xd9\x39\xb9\x38\x02\x00\x00\x0f\x84\xce\x00\x00\x00\x4c\x8b\x41\x28" base64
        $loader_ver_1_0_0_V1_x86_raw = {81 ec d4 02 00 00 53 55 56 8b b4 24 e4 02 00 00 33 db 57 8b fb 39 9e 38 02 00 00 0f 84 ea 00 00 00 ff 76 2c ff 76 28 ff b6 8c 00 00 00 ff b6 88}
        $loader_ver_1_0_0_V1_x86_b64 = "\x81\xec\xd4\x02\x00\x00\x53\x55\x56\x8b\xb4\x24\xe4\x02\x00\x00\x33\xdb\x57\x8b\xfb\x39\x9e\x38\x02\x00\x00\x0f\x84\xea\x00\x00\x00\xff\x76\x2c\xff\x76\x28\xff\xb6\x8c\x00\x00\x00\xff\xb6\x88" base64
        $loader_ver_0_9_3_V1_x64_raw = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 48 81 ec 00 05 00 00 33 ff 48 8b d9 48 39 b9 38 02 00 00 0f 84 c0 00 00 00 4c 8b 41 28 48 8b 91}
        $loader_ver_0_9_3_V1_x64_b64 = "\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x48\x81\xec\x00\x05\x00\x00\x33\xff\x48\x8b\xd9\x48\x39\xb9\x38\x02\x00\x00\x0f\x84\xc0\x00\x00\x00\x4c\x8b\x41\x28\x48\x8b\x91" base64
        $loader_ver_0_9_3_V2_x64_raw = {55 48 81 EC 30 05 00 00 48 8D AC 24 80 00 00 00 48 89 8D C0 04 00 00 48 C7 85 A8 04 00 00 00 00 00 00 48 8B 85 C0 04 00 00 48 8B 80 38 02 00 00}
        $loader_ver_0_9_3_V2_x64_b64 = "\x55\x48\x81\xEC\x30\x05\x00\x00\x48\x8D\xAC\x24\x80\x00\x00\x00\x48\x89\x8D\xC0\x04\x00\x00\x48\xC7\x85\xA8\x04\x00\x00\x00\x00\x00\x00\x48\x8B\x85\xC0\x04\x00\x00\x48\x8B\x80\x38\x02\x00\x00" base64
        $loader_ver_0_9_3_V1_x32_raw = {81 ec cc 02 00 00 53 55 56 8b b4 24 dc 02 00 00 33 db 57 8b fb 8b 86 38 02 00 00 0b 86 3c 02 00 00 0f 84 d4 00 00 00 ff 76 2c ff 76 28 ff b6 8c}
        $loader_ver_0_9_3_V1_x32_b64 = "\x81\xec\xcc\x02\x00\x00\x53\x55\x56\x8b\xb4\x24\xdc\x02\x00\x00\x33\xdb\x57\x8b\xfb\x8b\x86\x38\x02\x00\x00\x0b\x86\x3c\x02\x00\x00\x0f\x84\xd4\x00\x00\x00\xff\x76\x2c\xff\x76\x28\xff\xb6\x8c" base64
        $loader_ver_0_9_3_V2_x32_raw = {55 89 E5 56 53 81 EC 10 03 00 00 C7 45 F4 00 00 00 00 8B 4D 08 8B 99 3C 02 00 00 8B 89 38 02 00 00 89 CE 83 F6 00 89 F0 80 F7 00 89 DA 09 D0 85}
        $loader_ver_0_9_3_V2_x32_b64 = "\x55\x89\xE5\x56\x53\x81\xEC\x10\x03\x00\x00\xC7\x45\xF4\x00\x00\x00\x00\x8B\x4D\x08\x8B\x99\x3C\x02\x00\x00\x8B\x89\x38\x02\x00\x00\x89\xCE\x83\xF6\x00\x89\xF0\x80\xF7\x00\x89\xDA\x09\xD0\x85" base64
        $loader_ver_0_9_3_V3_x32_raw = {55 89 E5 56 53 81 EC 10 03 00 00 C7 45 F4 00 00 00 00 8B 45 08 8B 90 3C 02 00 00 8B 80 38 02 00 00 89 C6 83 F6 00 89 F1 89 D0 80 F4 00 89 C3 89}
        $loader_ver_0_9_3_V3_x32_b64 = "\x55\x89\xE5\x56\x53\x81\xEC\x10\x03\x00\x00\xC7\x45\xF4\x00\x00\x00\x00\x8B\x45\x08\x8B\x90\x3C\x02\x00\x00\x8B\x80\x38\x02\x00\x00\x89\xC6\x83\xF6\x00\x89\xF1\x89\xD0\x80\xF4\x00\x89\xC3\x89" base64
        $loader_ver_0_9_3_V4_x32_raw = {55 8B EC 81 EC 10 03 00 00 83 65 BC 00 6A 5C 68 0C B0 42 00 E8 67 C5 00 00 59 59 85 C0 74 14 6A 5C 68 1C B0 42 00 E8 55 C5 00 00 59 59 40 89 45}
        $loader_ver_0_9_3_V4_x32_b64 = "\x55\x8B\xEC\x81\xEC\x10\x03\x00\x00\x83\x65\xBC\x00\x6A\x5C\x68\x0C\xB0\x42\x00\xE8\x67\xC5\x00\x00\x59\x59\x85\xC0\x74\x14\x6A\x5C\x68\x1C\xB0\x42\x00\xE8\x55\xC5\x00\x00\x59\x59\x40\x89\x45" base64
        $loader_ver_0_9_2_V1_x64_raw = {55 48 89 e5 48 81 ec b0 00 00 00 48 89 4d 10 48 8b 45 10 48 89 45 e8 48 8b 45 e8 48 8b 40 48 48 89 45 e0 48 8b 45 e8 48 8b 48 28 48 8b 55 e0 48}
        $loader_ver_0_9_2_V1_x64_b64 = "\x55\x48\x89\xe5\x48\x81\xec\xb0\x00\x00\x00\x48\x89\x4d\x10\x48\x8b\x45\x10\x48\x89\x45\xe8\x48\x8b\x45\xe8\x48\x8b\x40\x48\x48\x89\x45\xe0\x48\x8b\x45\xe8\x48\x8b\x48\x28\x48\x8b\x55\xe0\x48" base64
        $loader_ver_0_9_2_V1_x86_raw = {83 ec 20 53 55 56 57 8b 7c 24 34 ff 77 2c ff 77 28 ff 77 4c ff 77 48 57 e8 d1 1a 00 00 ff 77 2c 8b f0 ff 77 28 ff 77 54 ff 77 50 57 e8 bd 1a 00}
        $loader_ver_0_9_2_V1_x86_b64 = "\x83\xec\x20\x53\x55\x56\x57\x8b\x7c\x24\x34\xff\x77\x2c\xff\x77\x28\xff\x77\x4c\xff\x77\x48\x57\xe8\xd1\x1a\x00\x00\xff\x77\x2c\x8b\xf0\xff\x77\x28\xff\x77\x54\xff\x77\x50\x57\xe8\xbd\x1a\x00" base64
        $loader_ver_0_9_1_V1_x64_raw = {48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 60 33 d2 48 8b f9 48 8d 4c 24 20 44 8d 42 40 e8 a2 10 00 00 44 8b 0f 4c 8d 47 24 41 83 e9 24 48 8d 57}
        $loader_ver_0_9_1_V1_x64_b64 = "\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xec\x60\x33\xd2\x48\x8b\xf9\x48\x8d\x4c\x24\x20\x44\x8d\x42\x40\xe8\xa2\x10\x00\x00\x44\x8b\x0f\x4c\x8d\x47\x24\x41\x83\xe9\x24\x48\x8d\x57" base64
        $loader_ver_0_9_1_V1_x86_raw = {83 ec 20 8d 04 24 53 55 56 57 6a 20 6a 00 50 e8 69 0e 00 00 8b 74 24 40 8b 06 83 e8 24 50 8d 46 24 50 8d 46 14 50 8d 46 04 50 e8 2a 0c 00 00 ff}
        $loader_ver_0_9_1_V1_x86_b64 = "\x83\xec\x20\x8d\x04\x24\x53\x55\x56\x57\x6a\x20\x6a\x00\x50\xe8\x69\x0e\x00\x00\x8b\x74\x24\x40\x8b\x06\x83\xe8\x24\x50\x8d\x46\x24\x50\x8d\x46\x14\x50\x8d\x46\x04\x50\xe8\x2a\x0c\x00\x00\xff" base64
        $loader_ver_0_9_0_V1_x64_raw = {55 48 89 e5 48 83 c4 80 48 89 4d 10 48 8b 45 10 48 89 45 f0 c7 45 ec 24 00 00 00 8b 55 ec 48 8b 45 f0 48 01 d0 48 89 45 e0 48 8b 45 f0 8b 00 2b}
        $loader_ver_0_9_0_V1_x64_b64 = "\x55\x48\x89\xe5\x48\x83\xc4\x80\x48\x89\x4d\x10\x48\x8b\x45\x10\x48\x89\x45\xf0\xc7\x45\xec\x24\x00\x00\x00\x8b\x55\xec\x48\x8b\x45\xf0\x48\x01\xd0\x48\x89\x45\xe0\x48\x8b\x45\xf0\x8b\x00\x2b" base64
        $loader_ver_0_9_0_V1_x86_raw = {55 89 e5 56 53 83 ec 60 8b 45 08 89 45 f0 c7 45 ec 24 00 00 00 8b 55 f0 8b 45 ec 01 d0 89 45 e8 8b 45 f0 8b 00 2b 45 ec 8b 55 f0 8d 4a 14 8b 55}
        $loader_ver_0_9_0_V1_x86_b64 = "\x55\x89\xe5\x56\x53\x83\xec\x60\x8b\x45\x08\x89\x45\xf0\xc7\x45\xec\x24\x00\x00\x00\x8b\x55\xf0\x8b\x45\xec\x01\xd0\x89\x45\xe8\x8b\x45\xf0\x8b\x00\x2b\x45\xec\x8b\x55\xf0\x8d\x4a\x14\x8b\x55" base64

    condition:
        any of them
}

rule upx_file {
    meta:
        description = "Ultimate Packer for Executables"
        type = "packer"
    strings:
        $a = {55505830000000}
        $b = {55505831000000}
        $c = "UPX!"
    condition:
        uint16(0) == 0x5A4D and
        $a in (0..1024) and
        $b in (0..1024) and
        $c in (0..1024)
}

// Installer Files
rule pyinstaller_file
{
    meta:
        type = "archive"
    strings:
        $ = { 4D 45 49 0C 0B 0A 0B 0E }
    condition:
        (
            uint16be(0) == 0x4d5a or
            uint32be(0) == 0x7f454c46 or
            uint32be(0) == 0xcefaedfe or
            uint32be(0) == 0xcffaedfe
        ) and
        all of them
}

// Script Files

rule batch_file {
    meta:
        type = "script"
    strings:
        $a = { ( 45 | 65 ) ( 43 | 63 ) ( 48 | 68 ) ( 4F | 6F ) 20 ( 4F | 6F) ( 46 | 66 ) ( 46 | 66 ) } // [Ee][Cc][Hh][Oo] [Oo][Ff][Ff]
    condition:
        $a at 0
}

rule jnlp_file {
    meta:
        description = "Detect JNLP (Java Network Launch Protocol) files"
        author = "Paul Hutelmyer"
        reference = "https://docs.oracle.com/javase/tutorial/deployment/webstart/deploying.html"
        type = "script"
    strings:
        $jnlp_header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" nocase
        $jnlp_tag = "<jnlp" nocase
    condition:
        $jnlp_header at 0 and $jnlp_tag
}

rule javascript_file {
    meta:
        type = "script"
    strings:
        $var = { 76 61 72 20 } // var
        $let = { 6C 65 74 20 } // let
        $function1 = { 66 75 6E 63 74 69 6F 6E } // function
        $function2 = { 28 66 75 6E 63 74 69 6F 6E } // (function
        $function3 = { 66 75 6E 63 74 69 6F 6E [0-1] 28 } // function[0-1](
        $if = { 69 66 [0-1] 28 } // if[0-1](
        $misc1 = { 24 28 } // $(
        $misc2 = { 2F ( 2A | 2F ) } // \/(\/|\*)
        $jquery = { 6A 51 75 65 72 79 } // jQuery
        $try = { 74 72 79 [0-1] 7B } // try[0-1]{
        $catch = { 63 61 74 63 68 28 } // catch(
        $push = { 2E 70 75 73 68 28 } // .push(
        $array = { 6E 65 77 20 41 72 72 61 79 28 } // new Array(
        $document1 = { 64 6f 63 75 6d 65 6e 74 2e 63 72 65 61 74 65 } // document.create
        $document2 = { 64 6F 63 75 6D 65 6E 74 2E 77 72 69 74 65 } // document.write
        $window = { 77 69 6E 64 6F 77 ( 2E | 5B ) } // window[.\[]
        $define = { 64 65 66 69 6E 65 28 } // define(
        $eval = { 65 76 61 6C 28 } // eval(
        $unescape = { 75 6E 65 73 63 61 70 65 28 } // unescape(
    condition:
        $var at 0 or
        $let at 0 or
        $function1 at 0 or
        $function2 at 0 or
        $if at 0 or
        $jquery at 0 or
        $function3 in (0..30) or
        $push in (0..30) or
        $array in (0..30) or
        ( $try at 0 and $catch in (5..5000) ) or
        $document1 in (0..100) or
        $document2 in (0..100) or
        $window in (0..100) or
        $define in (0..100) or
        $eval in (0..100) or
        $unescape in (0..100) or
        ( ( $misc1 at 0 or $misc2 at 0 ) and $var and $function1 and $if )
}

rule vb_file {
    meta:
        type = "script"
    strings:
        $a = { 41 74 74 72 69 62 75 74 65 20 56 42 5F 4E 61 6D 65 20 3D } // Attribute VB_Name =
        $b = { 4F 70 74 69 6F 6E 20 45 78 70 6C 69 63 69 74 } // Option Explicit
        $c = { 44 69 6D 20 } // Dim
        $d = { 50 75 62 6C 69 63 20 53 75 62 20 } // Public Sub
        $e = { 50 72 69 76 61 74 65 20 53 75 62 20 } // Private Sub
    condition:
        $a at 0 or
        $b at 0 or
        $c at 0 or
        $d at 0 or
        $e at 0
}

// Text Files

rule docx_file
{
	meta:
	    author = "Niels Warnars"
	    type = "document"
		description = "Word 2007 file format detection"
	strings:
		$header = { 50 4B 03 04 }
		$str = "document.xml"
	condition:
	   $header at 0 and $str
}

rule hta_file {
    meta:
        type = "text"
    strings:
        $a = { 3C 48 54 41 3A 41 50 50 4C 49 43 41 54 49 4F 4E 20 } // <HTA:APPLICATION
    condition:
        $a in (0..2000)
}

rule html_file {
    meta:
        type = "text"
    strings:
        $a = { 3C 21 ( 64 | 44 ) ( 6F | 4F ) ( 63 |43 ) ( 74 | 54 ) ( 79 | 59 ) ( 70 | 50 ) ( 65 | 45 )  20 ( 68 | 48 ) ( 74 | 54 ) ( 6D | 4D ) ( 6C | 4C )  } // <![Dd][Oo][Cc][Tt][Yy][Pp][Ee] [Hh][Tt][Mm][Ll]
        $b = { 3C ( 68 | 48 ) ( 74 | 54 ) ( 6D | 4D ) ( 6C | 4C ) } // <[Hh][Tt][Mm][Ll]
        $c = { 3C ( 62 | 42 ) ( 72 | 52 ) } // <br
        $d = { 3C ( 44 | 64 ) ( 49 | 69 ) ( 56 | 76 ) } // <[Dd][Ii][Vv]
        $e = { 3C ( 41 | 61 ) 20 ( 48 |68 ) ( 52 | 72 ) ( 45 | 65 ) ( 46 | 66 ) 3D } // <[Aa] [Hh][Rr][Ee][Ff]=
        $f = { 3C ( 48 | 68 ) ( 45 | 65 ) ( 41 | 61 ) ( 44 | 64 ) } // <[Hh][Ee][Aa][Dd]
        $g = { 3C ( 53 | 73 ) ( 43 | 63 ) ( 52 | 72 ) ( 49 | 69 ) ( 50 | 70 ) ( 54 | 74 ) } // <[Ss][Cc][Rr][Ii][Pp][Tt]
        $h = { 3C ( 53 | 73 ) ( 54 | 74 ) ( 59 | 79 ) ( 4C | 6C ) ( 45 | 65 ) } // <[Ss][Tt][Yy][Ll][Ee]
        $i = { 3C ( 54 | 74 ) ( 41 | 61 ) ( 42 | 62 ) ( 4C | 6C ) ( 45 | 65 ) } // <[Tt][Aa][Bb][Ll][Ee]
        $j = { 3C ( 50 | 70 ) } // <[Pp]
        $k = { 3C ( 49 | 69 ) ( 4D | 6D ) ( 47 | 67 ) } // <[Ii][Mm][Gg]
        $l = { 3C ( 53 | 73 ) ( 50 |70 ) ( 41 | 61 ) ( 4E | 6E ) } // <[Ss][Pp][Aa][Nn]
        $m = { 3C ( 48 | 68 ) ( 52 | 72 | 31 | 32 | 33 | 34 | 35 | 36 ) } // <[Hh][Rr] <[Hh][1-6]
        $n = { 3C ( 54 | 74) ( 49 | 69 ) ( 54 | 74 ) ( 4C | 6C ) ( 45 | 65 ) 3E } // <[Tt][Ii][Tt][Ll][Ee]>
    condition:
        $a at 0 or
        $b at 0 or
        $c at 0 or
        $d at 0 or
        $e at 0 or
        $f at 0 or
        $g at 0 or
        $h at 0 or
        $i at 0 or
        $j at 0 or
        $k at 0 or
        $l at 0 or
        $m at 0 or
        $n at 0
}

rule ini_file {
    meta:
        type = "text"
    strings:
        $a = /^\[[^\]\r\n]+](\r?\n([^[\r\n].*)?)*/ // section header pattern
    condition:
        filesize < 1KB and $a at 0
}

rule json_file {
    meta:
        type = "text"
    strings:
        $a = { 7B [0-5] 22 }
    condition:
        $a at 0
}

rule php_file {
    meta:
        type = "text"
    strings:
        $a = { 3c 3f 70 68 70 }
    condition:
        $a at 0
}

rule plist_file {
    meta:
        description =  "Property list (XML)"
        type = "text"
    strings:
        $a = { 3C 3F ( 58 | 78) ( 4D | 6D ) ( 4C | 6C ) 20 76 65 72 73 69 6F 6E 3D } // <?[Xx][Mm][Ll] version=
        $b = { 3c 21 44 4f 43 54 59 50 45 20 70 6c 69 73 74 } // <!DOCTYPE plist
    condition:
        $a at 0 and
        $b in (0..100)
}

rule soap_file {
    meta:
        description = "Simple Object Access Protocol"
        type = "text"
    strings:
        $a = { 3C 73 6F 61 70 65 6E 76 3A 45 6E 76 65 6C 6F 70 65 } // <soapenv:Envelope xmlns
        $b = { 3C 73 3A 45 6E 76 65 6C 6F 70 65 } // <s:Envelope
    condition:
        $a at 0 or
        $b at 0
}

rule xml_file {
    meta:
        type = "text"
    strings:
        $a = { 3C 3F ( 58 | 78) ( 4D | 6D ) ( 4C | 6C ) 20 76 65 72 73 69 6F 6E 3D } // <?[Xx][Mm][Ll] version=
        $b = { 3C 3F 78 6D 6C 3F 3E } // <?xml?>
        $c = { 3C 73 74 79 6C 65 53 68 65 65 74 20 78 6D 6C 6E 73 3D } // <styleSheet xmlns=
        $d = { 3C 77 6F 72 6B 62 6F 6F 6B 20 78 6D 6C 6E 73 } // <workbook xmlns
        $e = { 3C 78 6D 6C 20 78 6D 6C 6E 73 } // <xml xmlns
        $f = { 3C 69 6E 74 20 78 6D 6C 6E 73 } // <int xmlns
    condition:
        $a at 0 or
        $b at 0 or
        $c at 0 or
        $d at 0 or
        $e at 0 or
        $f at 0
}

// Video Files

rule avi_file {
    meta:
        type = "video"
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 41 56 49 20 4C 49 53 54 }
    condition:
        $a at 0
}

rule wmv_file {
    meta:
        type = "video"
    condition:
        uint32(0) == 0x75B22630 and uint32(4) == 0x11CF668E and uint32(8) == 0xAA00D9A6 and uint32(12) == 0x6CCE6200
}

// PII

rule credit_cards
{
    meta:
        // https://github.com/sbousseaden/YaraHunts/blob/master/hunt_creditcard_memscrap.yara
        // https://stackoverflow.com/questions/9315647/regex-credit-card-number-tests
        // https://moneytips.com/anatomy-of-a-credit-card/
        // https://engineering.avast.io/yara-in-search-of-regular-expressions/
        // https://baymard.com/checkout-usability/credit-card-patterns
        description = "Identify popular credit card numbers"
        author = "ryan.ohoro"
        date = "01/26/2023"
    strings:
        // $amex = /[^0-9]3[0-9]{14}[^0-9]/
        $visa = /[^0-9]4[0-9]{15}[^0-9]/
        // $mast = /[^0-9]5[0-9]{15}[^0-9]/
        // $disc = /[^0-9]6[0-9]{15}[^0-9]/
    condition:
        any of them
}

rule vsto_file
{
    meta:
        description = "Detects Microsoft Office VSTO files"
        reference = "https://www.deepinstinct.com/blog/no-macro-no-worries-vsto-being-weaponized-by-threat-actors"
        type = "text"
    strings:
        $ = "urn:schemas-microsoft-com:asm.v1"
        $ = /assemblyIdentity name=('|")[\w.]+\.vsto('|")/
        $ = /dependencyType=('|")install('|")/
        $ = /codebase=('|")[\w.]+\.manifest('|")/
    condition:
        magic.mime_type() == "text/xml" and
        all of them
}
