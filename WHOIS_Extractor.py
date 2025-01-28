#!/usr/bin/env python3
# hitem
# Req: pip install tqdm

import argparse
import subprocess
import re
from tqdm import tqdm  # Library for progress bar

class bcolors:
    HEADER = '\033[95m'
    OKGREEN = '\033[92m'
    OKCYAN = '\033[96m'
    OKGRAY = '\033[90m'
    OKRED = '\033[91m'
    WARNING = '\033[93m'
    INFO = '\033[94m'  # Informational responses color
    REDIRECT = '\033[93m'  # Orange for redirection messages
    SERVER_ERROR = '\033[94m'  # Blue for server error responses
    ENDC = '\033[0m'
    FAIL = '\033[91m'  # Red for failed connections

# Gradient color and logo functions
def interpolate_color(color1, color2, factor):
    """Interpolate between two RGB colors."""
    return [int(color1[i] + (color2[i] - color1[i]) * factor) for i in range(3)]

def rgb_to_ansi(r, g, b):
    """Convert RGB to ANSI color code."""
    return f'\033[38;2;{r};{g};{b}m'

def print_logo_and_instructions():
    logo = """
  ▄ .▄▪  ▄▄▄▄▄▄▄▄ .• ▌ ▄ ·. .▄▄ · ▄▄▄ . ▄▄·  
 ██▪▐███ •██  ▀▄.▀··██ ▐███▪▐█ ▀. ▀▄.▀·▐█ ▌▪ 
 ██▀▐█▐█· ▐█.▪▐▀▀▪▄▐█ ▌▐▌▐█·▄▀▀▀█▄▐▀▀▪▄██ ▄▄ 
 ██▌▐▀▐█▌ ▐█▌·▐█▄▄▌██ ██▌▐█▌▐█▄▪▐█▐█▄▄▌▐███▌ 
 ▀▀▀ ·▀▀▀ ▀▀▀  ▀▀▀ ▀▀  █▪▀▀▀ ▀▀▀▀  ▀▀▀ ·▀▀▀  
    """
    colors = [
        (255, 0, 255),  # Purple
        (0, 0, 255)     # Blue
    ]

    num_colors = len(colors)
    rainbow_logo = ""
    color_index = 0
    num_chars = sum(len(line) for line in logo.split("\n"))
    for char in logo:
        if char not in (" ", "\n"):
            factor = (color_index / num_chars) * (num_colors - 1)
            idx = int(factor)
            next_idx = min(idx + 1, num_colors - 1)
            local_factor = factor - idx
            color = interpolate_color(colors[idx], colors[next_idx], local_factor)
            rainbow_logo += rgb_to_ansi(*color) + char
            color_index += 1
        else:
            rainbow_logo += char

    instructions = f"""
    {rainbow_logo}{bcolors.ENDC}
    {bcolors.OKGRAY}Improve your reconnaissance by{bcolors.ENDC} {bcolors.OKRED}hitemSec{bcolors.ENDC}
    {bcolors.WARNING}---------------------------------{bcolors.ENDC}
    {bcolors.OKGRAY}This tool WHOIS domains!{bcolors.ENDC}

    {bcolors.WARNING}Usage:{bcolors.ENDC}
    {bcolors.OKGRAY}python3 .\\WHOISExtractor.py -l <input_file> -o <output_file> [-p]{bcolors.ENDC}

    {bcolors.OKGRAY}If you include the -p flag, the script will extract person, address, and phone fields as well.{bcolors.ENDC}
    """
    print(instructions)

# Display the logo & instructions
print_logo_and_instructions()

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='WHOIS script for a list of IP addresses.')
    parser.add_argument('-l', '--list', required=True, help='Path to the input file containing IP addresses.')
    parser.add_argument('-o', '--output', default='whois_results.txt',
                        help='Path to the output file (default: whois_results.txt).')
    parser.add_argument('-p', '--person', action='store_true',
                        help='Include person, address, and phone fields in the output.')
    args = parser.parse_args()
    
    input_file = args.list
    output_file = args.output
    include_person_fields = args.person

    # Regular expressions to extract required fields
    netname_regex = re.compile(r"netname:\s+(.+)", re.IGNORECASE)
    orgname_regex = re.compile(r"org-name:\s+(.+)", re.IGNORECASE)
    descr_regex = re.compile(r"descr:\s+(.+)", re.IGNORECASE)
    role_regex = re.compile(r"role:\s+(.+)", re.IGNORECASE)

    # These will only be used if -p is passed
    if include_person_fields:
        person_regex = re.compile(r"person:\s+(.+)", re.IGNORECASE)
        address_regex = re.compile(r"address:\s+(.+)", re.IGNORECASE)
        phone_regex = re.compile(r"phone:\s+(.+)", re.IGNORECASE)

    results = []

    # Read IP addresses from the input file
    with open(input_file, "r") as f:
        ip_addresses = [line.strip() for line in f if line.strip()]

    # Process each IP with a progress bar
    for ip in tqdm(ip_addresses, desc="Processing IPs", unit="IP"):
        try:
            # Run the whois command
            whois_output = subprocess.check_output(["whois", ip], text=True)
            
            # Extract basic fields
            netname_match = netname_regex.search(whois_output)
            orgname_match = orgname_regex.search(whois_output)
            descr_match = descr_regex.search(whois_output)
            role_match = role_regex.search(whois_output)

            netname = netname_match.group(1) if netname_match else "N/A"
            orgname = orgname_match.group(1) if orgname_match else "N/A"
            descr = descr_match.group(1) if descr_match else "N/A"
            role = role_match.group(1) if role_match else "N/A"

            # Determine organization to use
            organization = orgname
            if organization == "N/A":
                organization = descr
            if organization == "N/A":
                organization = role

            # Handle case where netname and descr are identical
            if netname == descr and role != "N/A":
                organization = role

            # Format the output
            formatted_result = f"{netname} ({ip}, {organization})"
            additional_info = f"[descr: {descr}] [role: {role}]"

            # If -p was supplied, extract additional contact fields
            if include_person_fields:
                person_matches = person_regex.findall(whois_output)
                address_matches = address_regex.findall(whois_output)
                phone_matches = phone_regex.findall(whois_output)

                person_info = ", ".join(person_matches) if person_matches else "N/A"
                address_info = ", ".join(address_matches) if address_matches else "N/A"
                phone_info = ", ".join(phone_matches) if phone_matches else "N/A"

                additional_info += f" [person: {person_info}] [address: {address_info}] [phone: {phone_info}]"

            formatted_result += f" {additional_info}"
            results.append(formatted_result)

        except subprocess.CalledProcessError as e:
            print(f"Error running whois for {ip}: {e}")
        except Exception as e:
            print(f"Unexpected error for {ip}: {e}")

    # Write results to the output file
    with open(output_file, "w") as f:
        for result in results:
            f.write(result + "\n")

    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
