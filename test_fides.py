#!/usr/bin/env python3
"""
Basic tests for Fides functionality
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, mock_open

# Add the parent directory to sys.path to import fides modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from run import _is_binary_file, _should_skip_file, download_file


class TestFidesFunctionality(unittest.TestCase):
    
    def test_should_skip_file(self):
        """Test file skipping logic"""
        # Should skip binary files
        self.assertTrue(_should_skip_file('test.pyc'))
        self.assertTrue(_should_skip_file('test.exe'))
        self.assertTrue(_should_skip_file('test.zip'))
        
        # Should skip files in certain directories
        self.assertTrue(_should_skip_file('.git/config'))
        self.assertTrue(_should_skip_file('__pycache__/test.py'))
        self.assertTrue(_should_skip_file('node_modules/package/index.js'))
        
        # Should not skip text files
        self.assertFalse(_should_skip_file('test.py'))
        self.assertFalse(_should_skip_file('README.md'))
        self.assertFalse(_should_skip_file('config.yml'))
    
    def test_is_binary_file(self):
        """Test binary file detection"""
        # Create temporary text file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('This is a text file\n')
            text_file = f.name
        
        # Create temporary binary file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'\x00\x01\x02\x03')
            binary_file = f.name
        
        try:
            self.assertFalse(_is_binary_file(text_file))
            self.assertTrue(_is_binary_file(binary_file))
        finally:
            os.unlink(text_file)
            os.unlink(binary_file)
    
    @patch('run.urlopen')
    def test_download_file(self, mock_urlopen):
        """Test file download functionality"""
        # Mock successful response
        mock_response = mock_open(read_data=b'test content')
        mock_response.return_value.status = 200
        mock_urlopen.return_value.__enter__ = mock_response
        mock_urlopen.return_value.__exit__ = lambda *args: None
        
        result = download_file('http://example.com/test.txt')
        self.assertEqual(result, 'test content')
        
        # Mock failed response
        mock_response.return_value.status = 404
        result = download_file('http://example.com/missing.txt')
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()