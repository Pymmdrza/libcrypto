#!/usr/bin/env python3
"""
Direct test of SHA256 module to bypass import chain issues
"""

import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import SHA256 directly
try:
    from libcrypto.Hash.SHA256 import new, get_implementation
    print("✅ SHA256 import successful!")
    print(f"Implementation: {get_implementation()}")
    
    # Test basic functionality
    test_data = b"Hello, World!"
    hasher = new(test_data)
    hash_result = hasher.hexdigest()
    print(f"SHA256('{test_data.decode()}'): {hash_result}")
    
    # Test expected hash
    expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    if hash_result == expected:
        print("✅ Hash result matches expected value!")
    else:
        print(f"❌ Hash mismatch. Expected: {expected}")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc() 