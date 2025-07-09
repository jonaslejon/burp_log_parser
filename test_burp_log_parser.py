#!/usr/bin/env python3
"""
Test suite for Burp Suite Log Parser

Run tests with: pytest test_burp_log_parser.py -v
Or just: pytest (for automatic discovery)
"""

import pytest
import tempfile
import json
import base64
import xml.etree.ElementTree as ET
from unittest.mock import patch, mock_open
import sys
import os

# Import the module to test
import burp_log_parser


class TestBurpLogParser:
    """Test suite for the Burp Suite Log Parser"""

    @pytest.fixture
    def sample_request(self):
        """Sample HTTP request"""
        return """GET /test HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: */*
"""

    @pytest.fixture
    def sample_response(self):
        """Sample HTTP response"""
        return """HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 13

Hello, World!"""

    @pytest.fixture
    def sample_xml_content(self, sample_request, sample_response):
        """Create sample XML content"""
        request_b64 = base64.b64encode(sample_request.encode()).decode()
        response_b64 = base64.b64encode(sample_response.encode()).decode()
        
        return f"""<?xml version="1.0"?>
<items>
    <item>
        <time>Mon Jan 01 12:00:00 UTC 2025</time>
        <url>http://example.com/test</url>
        <host>example.com</host>
        <port>80</port>
        <protocol>http</protocol>
        <method>GET</method>
        <status>200</status>
        <responselength>13</responselength>
        <mimetype>text/html</mimetype>
        <comment>Test comment</comment>
        <request>{request_b64}</request>
        <response>{response_b64}</response>
    </item>
</items>"""

    @pytest.fixture
    def sample_csv_content(self, sample_request, sample_response):
        """Create sample CSV content"""
        request_b64 = base64.b64encode(sample_request.encode()).decode()
        response_b64 = base64.b64encode(sample_response.encode()).decode()
        
        return f"""ID,Time,Tool,Method,Protocol,Host,Port,URL,Status code,Length,MIME type,Comment,Request,Response
0,Mon Jan 01 12:00:00 UTC 2025,Burp Suite,GET,http,example.com,80,http://example.com/test,200,13,text/html,Test comment,{request_b64},{response_b64}"""

    @pytest.fixture
    def xml_file(self, sample_xml_content):
        """Create a temporary XML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(sample_xml_content)
            f.flush()
            yield f.name
        os.unlink(f.name)

    @pytest.fixture
    def csv_file(self, sample_csv_content):
        """Create a temporary CSV file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(sample_csv_content)
            f.flush()
            yield f.name
        os.unlink(f.name)

    def test_parse_xml(self, xml_file):
        """Test parsing XML file"""
        entries = burp_log_parser.parse_xml(xml_file)
        
        assert len(entries) == 1
        assert entries[0]['Host'] == 'example.com'
        assert entries[0]['Method'] == 'GET'
        assert entries[0]['Status code'] == '200'
        assert entries[0]['URL'] == 'http://example.com/test'

    def test_parse_csv(self, csv_file):
        """Test parsing CSV file"""
        entries = burp_log_parser.parse_csv(csv_file)
        
        assert len(entries) == 1
        assert entries[0]['Host'] == 'example.com'
        assert entries[0]['Method'] == 'GET'
        assert entries[0]['Status code'] == '200'
        assert entries[0]['URL'] == 'http://example.com/test'

    def test_decode_base64_request_response(self, csv_file, capsys):
        """Test base64 decoding of requests and responses"""
        burp_log_parser.decode_burp_log(csv_file, None, None, None, False, False)
        captured = capsys.readouterr()
        
        assert "GET /test HTTP/1.1" in captured.out
        assert "Host: example.com" in captured.out
        assert "HTTP/1.1 200 OK" in captured.out
        assert "Hello, World!" in captured.out

    def test_status_code_filter(self, csv_file, capsys):
        """Test filtering by status code"""
        # Should show results for 200
        burp_log_parser.decode_burp_log(csv_file, "200", None, None, False, False)
        captured = capsys.readouterr()
        assert "Host: example.com" in captured.out
        
        # Should not show results for 404
        burp_log_parser.decode_burp_log(csv_file, "404", None, None, False, False)
        captured = capsys.readouterr()
        assert "Host: example.com" not in captured.out

    def test_response_filter(self, csv_file, capsys):
        """Test filtering by response content"""
        # Should find "Hello"
        burp_log_parser.decode_burp_log(csv_file, None, "Hello", None, False, False)
        captured = capsys.readouterr()
        assert "Host: example.com" in captured.out
        
        # Should not find "Goodbye"
        burp_log_parser.decode_burp_log(csv_file, None, "Goodbye", None, False, False)
        captured = capsys.readouterr()
        assert "Host: example.com" not in captured.out

    def test_response_only_mode(self, csv_file, capsys):
        """Test response-only output mode"""
        burp_log_parser.decode_burp_log(csv_file, None, None, None, True, False)
        captured = capsys.readouterr()
        
        # Should show response but not request
        assert "HTTP/1.1 200 OK" in captured.out
        assert "Hello, World!" in captured.out
        assert "GET /test HTTP/1.1" not in captured.out
        assert "ID:" not in captured.out

    def test_json_output(self, csv_file, capsys):
        """Test JSON output format"""
        burp_log_parser.decode_burp_log(csv_file, None, None, None, False, True)
        captured = capsys.readouterr()
        
        # Should be valid JSON
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]['Host'] == 'example.com'
        assert "GET /test HTTP/1.1" in data[0]['Decoded HTTP Request']
        assert "Hello, World!" in data[0]['Decoded HTTP Response']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
