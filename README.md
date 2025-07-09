# Burp Suite Log Parser

A Python script that parses Burp Suite log files (XML or CSV format), decodes base64-encoded HTTP requests and responses, and displays them in a human-readable format with colored terminal output.

## Features

- **Multi-format Support**: Parses both XML and CSV Burp Suite log files
- **Base64 Decoding**: Automatically decodes base64-encoded HTTP requests and responses
- **Colored Output**: Uses terminal colors for better readability
- **Advanced Filtering**: Filter results by status code, response content, or exclude specific patterns
- **Flexible Output**: Display full request/response data or response-only mode
- **JSON Export**: Export parsed data as JSON for further processing
- **Regex Support**: Use regular expressions for advanced content filtering

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/burp-suite-log-parser.git
cd burp-suite-log-parser
```

2. Install required dependencies:
```bash
pip install termcolor
```

## Usage

### Basic Usage

```bash
python burp_log_parser.py <input_file>
```

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `input_file` | Path to the Burp Suite log file (required) | `burp_log.xml` |
| `--status_code` | Filter results by HTTP status code | `--status_code 200` |
| `--filter_response` | Filter by response content (supports regex, comma-separated) | `--filter_response "error,404"` |
| `--negative_filter_response` | Exclude results matching patterns (supports regex, comma-separated) | `--negative_filter_response "success,200 OK"` |
| `--response_only` | Only display HTTP response data | `--response_only` |
| `--json_output` | Export results as JSON | `--json_output` |

### Examples

1. **Parse a basic Burp log file:**
```bash
python burp_log_parser.py burp_log.xml
```

2. **Filter by status code 404:**
```bash
python burp_log_parser.py burp_log.csv --status_code 404
```

3. **Find responses containing "error" or "exception":**
```bash
python burp_log_parser.py burp_log.xml --filter_response "error,exception"
```

4. **Exclude successful responses:**
```bash
python burp_log_parser.py burp_log.csv --negative_filter_response "200 OK,success"
```

5. **Use regex to find email addresses in responses:**
```bash
python burp_log_parser.py burp_log.xml --filter_response "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
```

6. **Export results as JSON:**
```bash
python burp_log_parser.py burp_log.xml --json_output > results.json
```

7. **Show only responses for 500 errors:**
```bash
python burp_log_parser.py burp_log.csv --status_code 500 --response_only
```

## Output Format

### Standard Output
The script displays each log entry with the following information:
- ID
- Time
- Tool
- Method
- Protocol
- Host
- Port
- URL
- Status Code
- Length
- MIME Type
- Comment
- Decoded HTTP Request (in green)
- Decoded HTTP Response (in yellow)

### JSON Output
When using `--json_output`, the script outputs a JSON array containing all parsed entries with decoded request and response data.

## Color Coding

- **Cyan**: Section headers (e.g., "Decoded HTTP Request:")
- **Green**: HTTP request data
- **Yellow**: HTTP response data

## Supported File Formats

### XML Format
The script automatically detects XML files by extension or content. Burp Suite XML logs should follow the standard Burp format with `<item>` elements containing request/response data.

### CSV Format
CSV files should include standard Burp Suite export columns. The script automatically handles large CSV files by adjusting field size limits.

## Error Handling

- The script gracefully handles non-base64 encoded content
- UTF-8 decoding errors are ignored to prevent crashes
- File parsing errors are reported to stderr

## Requirements

- Python 3.x
- termcolor library

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Troubleshooting

### Common Issues

1. **"Error parsing file"**: Ensure the input file is a valid Burp Suite log in XML or CSV format
2. **Encoding errors**: The script uses UTF-8 with error ignoring, but some special characters may not display correctly
3. **Large files**: For very large log files, consider using filters to reduce output or export to JSON for processing

### Performance Tips

- Use status code filtering to reduce processing time
- Combine multiple filters for more targeted results
- Use `--response_only` when you don't need request data
- Export to JSON for programmatic processing of large datasets

## Author

[Your Name]

## Acknowledgments

- Built for the security research community
- Inspired by the need for better Burp Suite log analysis tools