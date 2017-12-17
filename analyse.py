import pefile
pe = pefile.PE('C:\Users\Funani Ndou\Downloads\Programs\WinSCP-5.9.6-Setup.exe')

print ' This is the optional header\n' + hex(pe.OPTIONAL_HEADER.ImageBase)

print ' This is the Number of RV and SIZES\n' +hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)

print ' This is the Number of Sections\n' + hex(pe.FILE_HEADER.NumberOfSections)



#function to check and print sections in pe file
for section in pe.sections:
    
    print(section.Name,
    hex(section.VirtualAddress),
    hex(section.Misc_VirtualSize),
    section.SizeOfRawData)

