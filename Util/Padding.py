"""
Padding utilities for block ciphers.

This module provides PKCS#7 and other padding schemes.
"""

from typing import Union


def pad(data_to_pad: bytes, block_size: int, style: str = 'pkcs7') -> bytes:
    """
    Apply padding to data.
    
    Args:
        data_to_pad: Data to pad
        block_size: Block size in bytes
        style: Padding style ('pkcs7', 'iso7816', 'x923')
        
    Returns:
        Padded data
    """
    if block_size < 1 or block_size > 255:
        raise ValueError("Block size must be between 1 and 255")
    
    padding_len = block_size - (len(data_to_pad) % block_size)
    
    if style == 'pkcs7':
        padding = bytes([padding_len]) * padding_len
    elif style == 'iso7816':
        padding = b'\x80' + (b'\x00' * (padding_len - 1))
    elif style == 'x923':
        padding = (b'\x00' * (padding_len - 1)) + bytes([padding_len])
    else:
        raise ValueError(f"Unknown padding style: {style}")
    
    return data_to_pad + padding


def unpad(padded_data: bytes, block_size: int, style: str = 'pkcs7') -> bytes:
    """
    Remove padding from data.
    
    Args:
        padded_data: Padded data
        block_size: Block size in bytes
        style: Padding style ('pkcs7', 'iso7816', 'x923')
        
    Returns:
        Unpadded data
    """
    if len(padded_data) == 0 or len(padded_data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    
    if style == 'pkcs7':
        padding_len = padded_data[-1]
        if padding_len < 1 or padding_len > block_size:
            raise ValueError("Invalid PKCS#7 padding")
        
        # Check all padding bytes
        padding = padded_data[-padding_len:]
        if padding != bytes([padding_len]) * padding_len:
            raise ValueError("Invalid PKCS#7 padding")
        
        return padded_data[:-padding_len]
    
    elif style == 'iso7816':
        # Find the 0x80 byte from the end
        for i in range(len(padded_data) - 1, -1, -1):
            if padded_data[i] == 0x80:
                # Check that all bytes after 0x80 are 0x00
                padding = padded_data[i + 1:]
                if all(b == 0 for b in padding):
                    return padded_data[:i]
                break
        raise ValueError("Invalid ISO 7816-4 padding")
    
    elif style == 'x923':
        padding_len = padded_data[-1]
        if padding_len < 1 or padding_len > block_size:
            raise ValueError("Invalid ANSI X9.23 padding")
        
        # Check all padding bytes (should be 0x00 except the last)
        padding = padded_data[-padding_len:-1]
        if padding != b'\x00' * (padding_len - 1):
            raise ValueError("Invalid ANSI X9.23 padding")
        
        return padded_data[:-padding_len]
    
    else:
        raise ValueError(f"Unknown padding style: {style}") 