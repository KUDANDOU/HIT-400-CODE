import pefile

exe_path = "C:\Users\Funani Ndou\Desktop\HIT 400 TINGZ\HIT 400 CODE\heroku-cli-x64.exe"
pe = pefile.PE(exe_path)

# print("[*] e_magic value: %s" % hex(pe.DOS_HEADER.e_magic))
# print("[*] Signature value: %s" % hex(pe.NT_HEADERS.Signature))


print (pe.FileInfo)