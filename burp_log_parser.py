#!/usr/bin/env python3
"""
Burp Suite Log Parser for XML and CSV

This script parses a Burp Suite log file (in XML or CSV format), decodes base64-encoded HTTP requests and responses,
and prints them in a human-readable format with colored output for better readability.

Usage:
    python burp_log_parser.py <input_file> --status_code <status_code> --filter_response <filter_response> --negative_filter_response <negative_filter_response> --response_only --json_output

Dependencies:
    - termcolor: Install using `pip install termcolor`

"""

import csv
import base64
import argparse
import re
import json
import sys
import xml.etree.ElementTree as ET
from termcolor import colored

def parse_xml(file_path):
    """Parses a Burp Suite XML log file."""
    tree = ET.parse(file_path)
    root = tree.getroot()
    log_entries = []
    for i, item in enumerate(root.findall('item')):
        log_entry = {
            "ID": str(i),
            "Time": item.find('time').text,
            "Tool": "Burp Suite",
            "Method": item.find('method').text,
            "Protocol": item.find('protocol').text,
            "Host": item.find('host').text,
            "Port": item.find('port').text,
            "URL": item.find('url').text,
            "Status code": item.find('status').text,
            "Length": item.find('responselength').text,
            "MIME type": item.find('mimetype').text,
            "Comment": item.find('comment').text,
            "Request": item.find('request').text if item.find('request') is not None else None,
            "Response": item.find('response').text if item.find('response') is not None else None,
        }
        log_entries.append(log_entry)
    return log_entries

def parse_csv(file_path):
    """Parses a Burp Suite CSV log file."""
    log_entries = []
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            log_entries.append(row)
    return log_entries

def decode_burp_log(file_path, filter_status_code, filter_response, negative_filter_response, response_only, json_output):
    log_entries = []

    # Detect file type and parse accordingly
    try:
        if file_path.lower().endswith('.xml') or b'<?xml' in open(file_path, 'rb').read(100):
            raw_entries = parse_xml(file_path)
        else:
            # Increase CSV field size limit to avoid field limit error
            csv.field_size_limit(sys.maxsize)
            raw_entries = parse_csv(file_path)
    except Exception as e:
        print(f"Error parsing file: {e}", file=sys.stderr)
        sys.exit(1)


    for row in raw_entries:
        # Filter based on status code if provided
        if filter_status_code and row.get('Status code') != filter_status_code:
            continue

        response = None
        # Decode the base64-encoded HTTP response if it exists
        if 'Response' in row and row['Response']:
            try:
                response = base64.b64decode(row['Response']).decode('utf-8', 'ignore')
            except (base64.binascii.Error, TypeError):
                response = row['Response'] # Assume not base64 encoded

            # Filter based on response content if provided (supports both text and regex)
            if filter_response:
                filter_patterns = filter_response.split(',')
                if not any(re.search(pattern.strip(), response) for pattern in filter_patterns):
                    continue
            # Filter out responses that match the negative filter (supports both text and regex)
            if negative_filter_response:
                negative_patterns = negative_filter_response.split(',')
                if any(re.search(pattern.strip(), response) for pattern in negative_patterns):
                    continue

        # If response_only flag is set, only print the response
        if response_only:
            if response:
                print(colored(response, "yellow"))
            print("\n")
            continue

        # Decode the base64-encoded HTTP request
        if 'Request' not in row or not row['Request']:
            continue
        
        try:
            decoded_request = base64.b64decode(row['Request']).decode('utf-8', 'ignore')
        except (base64.binascii.Error, TypeError):
            decoded_request = row['Request'] # Assume not base64 encoded


        # Collect data for JSON output
        log_entry = {
            "ID": row.get('ID'),
            "Time": row.get('Time'),
            "Tool": row.get('Tool'),
            "Method": row.get('Method'),
            "Protocol": row.get('Protocol'),
            "Host": row.get('Host'),
            "Port": row.get('Port'),
            "URL": row.get('URL'),
            "Status Code": row.get('Status code'),
            "Length": row.get('Length'),
            "MIME Type": row.get('MIME type'),
            "Comment": row.get('Comment'),
            "Decoded HTTP Request": decoded_request,
            "Decoded HTTP Response": response
        }
        log_entries.append(log_entry)

        # Skip printing if JSON output is selected
        if json_output:
            continue

        # Print general information about the HTTP request/response
        print(f"ID: {row.get('ID')}")
        print(f"Time: {row.get('Time')}")
        print(f"Tool: {row.get('Tool')}")
        print(f"Method: {row.get('Method')}")
        print(f"Protocol: {row.get('Protocol')}")
        print(f"Host: {row.get('Host')}")
        print(f"Port: {row.get('Port')}")
        print(f"URL: {row.get('URL')}")
        print(f"Status Code: {row.get('Status code')}")
        print(f"Length: {row.get('Length')}")
        print(f"MIME Type: {row.get('MIME type')}")
        print(f"Comment: {row.get('Comment')}")
        print("\n")
        print(colored("Decoded HTTP Request:", "cyan"))
        # Print the decoded HTTP request in green color
        print(colored(decoded_request, "green"))

        # Print the decoded HTTP response if it exists
        if response:
            print("\n")
            print(colored("Decoded HTTP Response:", "cyan"))
            # Print the decoded HTTP response in yellow color
            print(colored(response, "yellow"))

        print("\n")

    # Print the output as JSON if the json_output flag is set
    if json_output:
        print(json.dumps(log_entries, indent=4))

def main():
    # Set up argument parser to take input file, status code, and response filter from command line
    parser = argparse.ArgumentParser(description='Parse and decode Burp Suite log file (XML or CSV).')
    parser.add_argument('input_file', type=str, help='Path to the Burp Suite log file')
    parser.add_argument('--status_code', type=str, help='Filter results by HTTP status code', default=None)
    parser.add_argument('--filter_response', type=str, help='Filter results by HTTP response content (supports text and regex, multiple patterns separated by commas)', default=None)
    parser.add_argument('--negative_filter_response', type=str, help='Exclude results by HTTP response content (supports text and regex, multiple patterns separated by commas)', default=None)
    parser.add_argument('--response_only', action='store_true', help='Only print the HTTP response data')
    parser.add_argument('--json_output', action='store_true', help='Print the output as JSON')
    args = parser.parse_args()

    # Call the function to decode the Burp log with optional filters
    decode_burp_log(args.input_file, args.status_code, args.filter_response, args.negative_filter_response, args.response_only, args.json_output)

if __name__ == "__main__":
    main()