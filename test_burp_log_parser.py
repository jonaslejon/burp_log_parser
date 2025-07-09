"""
pytest configuration file with shared fixtures and test utilities
"""

import pytest
import tempfile
import base64
import os


@pytest.fixture
def create_burp_xml_file():
    """Factory fixture to create Burp XML files with custom content"""
    def _create_file(items):
        xml_content = '<?xml version="1.0"?>\n<items>\n'
        
        for item in items:
            xml_content += '    <item>\n'
            for key, value in item.items():
                if key in ['request', 'response'] and value:
                    # Base64 encode request/response
                    value = base64.b64encode(value.encode()).decode()
                xml_content += f'        <{key}>{value}</{key}>\n'
            xml_content += '    </item>\n'
        
        xml_content += '</items>'
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(xml_content)
            f.flush()
            return f.name
    
    yield _create_file
    
    # Cleanup any created files
    for file in tempfile.gettempdir():
        if file.endswith('.xml') and os.path.exists(file):
            try:
                os.unlink(file)
            except:
                pass


@pytest.fixture
def create_burp_csv_file():
    """Factory fixture to create Burp CSV files with custom content"""
    def _create_file(rows):
        headers = ['ID', 'Time', 'Tool', 'Method', 'Protocol', 'Host', 'Port', 
                  'URL', 'Status code', 'Length', 'MIME type', 'Comment', 
                  'Request', 'Response']
        
        csv_content = ','.join(headers) + '\n'
        
        for i, row in enumerate(rows):
            row_data = []
            for header in headers:
                value = row.get(header, '')
                if header in ['Request', 'Response'] and value:
                    # Base64 encode request/response
                    value = base64.b64encode(value.encode()).decode()
                row_data.append(str(value))
            csv_content += ','.join(row_data) + '\n'
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(csv_content)
            f.flush()
            return f.name
    
    yield _create_file
    
    # Cleanup any created files
    for file in tempfile.gettempdir():
        if file.endswith('.csv') and os.path.exists(file):
            try:
                os.unlink(file)
            except:
                pass


@pytest.fixture
def sample_http_requests():
    """Collection of sample HTTP requests for testing"""
    return {
        'simple_get': """GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0

""",
        'post_with_data': """POST /api/login HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Length: 42

{"username": "test", "password": "secret"}""",
        'with_sql_error': """GET /search?q=test' HTTP/1.1
Host: vulnerable.com

""",
    }


@pytest.fixture
def sample_http_responses():
    """Collection of sample HTTP responses for testing"""
    return {
        'success': """HTTP/1.1 200 OK
Content-Type: text/html

<html><body>Success</body></html>""",
        'error_404': """HTTP/1.1 404 Not Found
Content-Type: text/html

<html><body>Page not found</body></html>""",
        'json_with_email': """HTTP/1.1 200 OK
Content-Type: application/json

{"user": "test@example.com", "status": "active"}""",
        'sql_error': """HTTP/1.1 500 Internal Server Error
Content-Type: text/html

<html><body>
<h1>Database Error</h1>
<p>MySQL Error: You have an error in your SQL syntax near 'test'</p>
</body></html>""",
        'api_key_exposed': """HTTP/1.1 200 OK
Content-Type: application/json

{"api_key": "sk-1234567890abcdef", "endpoint": "https://api.example.com"}""",
    }


@pytest.fixture
def mock_colored(monkeypatch):
    """Mock the termcolor.colored function to return plain text"""
    def _colored(text, color):
        return text
    
    monkeypatch.setattr('termcolor.colored', _colored)
    return _colored
