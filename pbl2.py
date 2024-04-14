import os
import sys
import hashlib
import pefile

def scan_file(file_path):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    # Calculate the MD5 hash of the file
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    print(f"MD5 hash: {md5_hash.hexdigest()}")

    # Parse the PE file
    try:
        pe = pefile.PE(file_path)
        print("PE File information:")
        print(f"  Machine: 0x{pe.FILE_HEADER.Machine:04x}")
        print(f"  Characteristics: 0x{pe.FILE_HEADER.Characteristics:04x}")
        print(f"  Number of sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"  Entry point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}")
    except pefile.PEFormatError as e:
        print(f"Error parsing PE file: {e}")

    try:
        pe = pefile.PE(file_path)
        # Estimate CPU usage based on factors like code size, number of functions, etc.
        code_section = pe.sections[0]
        code_size = code_section.SizeOfRawData
        number_of_functions = len(pe.DIRECTORY_ENTRY_IMPORT)
        estimated_cpu_usage = code_size * number_of_functions
        print(f"Estimated CPU usage: {estimated_cpu_usage}")
    except pefile.PEFormatError as e:
        print(f"Error parsing PE file: {e}")

    try:
        pe = pefile.PE(file_path)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"Imported DLL: {entry.dll}")
            for imp in entry.imports:
                print(f"  Function: {imp.name}")
    except Exception as e:
        print(f"Error analyzing PE file: {e}")




if __name__ == "__main__":
    file_path = 'audiorelay-0.27.5.exe'
    scan_file(file_path)
