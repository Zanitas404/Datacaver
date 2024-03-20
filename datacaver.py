import pykd, sys, argparse, re

prot_constants = [0x04]	# Protection constants to check if the memory region is executable
running_addr = 0				# Used to skip the current code cave (recursion yay)


def analyze_cave(start_addr):
	global running_addr
	flag = True					                                                              # Used to find the end of the data cave
	counter = 0					                                                              # Used to move through the memory region
	while flag:
		out = pykd.dbgCommand('dd ({0} + 4 * 0n{1}) L4'.format(start_addr, counter))		# Display the memory region
		counter = counter + 1 																                          # Move forward in the memory region
		if not '00000000 00000000 00000000 00000000' in out:								            # Checks if the region stores data
			flag = False																	                                # If it does, the flag will be inverted and the loop ends
			out = pykd.dbgCommand('dd ({0} + 4 * 0n{1}) L4'.format(start_addr, counter - 1))	# Obtain the end of the code cave
			running_addr = int(out.split('  ')[0], 16)										                # Obtain the end addr of the code cave in order to move on to the next one
	code_cave_size = (counter + 1 ) * 4														                    # Calculate the data cave size using the counter
	pykd.dprintln('|\t{0}\t|\t\t{1}\t\t|'.format(start_addr, code_cave_size))


def vprot(addr):
	out = pykd.dbgCommand('!vprot {0}'.format(addr))
	out = out.split('Protect:           ')[1].split(' ')[0]			                      # Obtain the hex value of the protection value
	try:
		out = int(out, 16)											                                        # Convert the string to int base 16
	except Exception as e:
		pykd.dprintln(e)
	
	if out in prot_constants:										                                      # If the memory region is executable -> return the address
		analyze_cave(addr)


def analyze(input):
	out_arr = input.split('\n')
	for x in out_arr:
		if '00000000 00000000 00000000 00000000' in x:				                          # Check if the region is empty
			vprot(x.split('  ')[0])							                                          # If it is, move to vprot() in order to analyze it further		

			
def looper(start, end):												                                      # This method is used in order to skip a data cave if one is found
	global running_addr												                                        # So that the script does not analyze the same cave multiple times
	for address in range(start, end, 0xA):
		if running_addr != 0:
			tmp = running_addr
			running_addr = 0
			looper(tmp, end)
			return
		out = pykd.dbgCommand('dd {0} L100'.format(hex(address)))
		analyze(out)


def print_welcome_message():
	pykd.dprintln('''
                                                                              
                                                                              
██████╗  █████╗ ████████╗ █████╗      ██████╗ █████╗ ██╗   ██╗███████╗██████╗ 
██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗    ██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
██║  ██║███████║   ██║   ███████║    ██║     ███████║██║   ██║█████╗  ██████╔╝
██║  ██║██╔══██║   ██║   ██╔══██║    ██║     ██╔══██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
██████╔╝██║  ██║   ██║   ██║  ██║    ╚██████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝     ╚═════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
                                                                              
 											written by Ghostduck
                      inspired by nop
		''')


def main():
	parser = argparse.ArgumentParser(description='Search for data caves in loaded modules / the binary')
	parser.add_argument('module', metavar='modulename', type=str, help='Enter the name of the module')

	args = parser.parse_args()

	print_welcome_message()



	pykd.dprintln('[*] Scanning for data caves in module {0}\n'.format(args.module))

	module_addresses = pykd.dbgCommand('lm m {0}'.format(args.module))
	pattern_addresses = r"(\b[0-9A-F]+\b) \b[0-9A-F]+\b .+"
	match_new = re.search(pattern_addresses, module_addresses)
	start_value = match_new.group(1) if match_new else None
	pykd.dprintln('Module Information:')
	pykd.dprintln('==========================')
	
	pykd.dprintln('Start-Address:\t' + start_value + '\n')


	out = pykd.dbgCommand('!dh -a {0}'.format(args.module))
	sections = out.split("SECTION HEADER")
	for section in sections:
		if ".data name" in section:
			pattern = r"([0-9A-F]+) virtual (size|address)"
			matches = re.findall(pattern, section)
			extracted_values = {match[1]: match[0] for match in matches}
			virtual_size = extracted_values.get("size")
			virtual_address = extracted_values.get("address")


			pykd.dprintln('.data Information:')
			pykd.dprintln('==========================')
			pykd.dprintln('Virtual Address (Offset):\t' + virtual_address)
			pykd.dprintln('Virtual Size:\t\t\t' + virtual_size)

			virtual_address_int = int(virtual_address, 16)
			virtual_size_int = int(virtual_size, 16)
			start_value_int = int(start_value, 16)
			data_section_start = start_value_int + virtual_address_int
			data_section_end = start_value_int + virtual_address_int + virtual_size_int
			pykd.dprintln('RW Address:\t\t\t' + hex(data_section_end)[2:])

			pykd.dprintln('\n.data Protections:')
			pykd.dprintln('===================================================')	
			prot = pykd.dbgCommand('!vprot ' + hex(data_section_end)[2:])
			pykd.dprintln(prot)

			pattern_memory = r"(BaseAddress|RegionSize):\s+([0-9A-F]+)"
			matches_memory = re.findall(pattern_memory, prot, re.IGNORECASE)
			extracted_values_memory = {match[0]: match[1] for match in matches_memory}
			base_address = extracted_values_memory.get("BaseAddress")
			region_size = extracted_values_memory.get("RegionSize")
			base_address_int = int(base_address, 16)
			region_size_int = int(region_size, 16)
			sum_address = base_address_int + region_size_int
			end_address_int = hex(sum_address)[2:].upper()
	
	
	pykd.dprintln('\nData Caves')
	pykd.dprintln('===========================================')
	
	pykd.dprintln('|\tAddress\t|\tSize (Bytes)\t|')
	looper(base_address_int, sum_address)	

    #looper(start, end)

	pykd.dprintln('\n[*] DONE\n\n')

if __name__ == '__main__':
	main()
