import streamlit as st
import random
import time
from Crypto.Cipher import AES
import networkx as nx
import matplotlib.pyplot as plt

# AES encryption
def aes_encrypt(data, key):
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

# AES decryption
def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# Character stuffing
def character_stuff(data):
    stuffed = bytearray()
    for byte in data:
        if byte in (0x7E, 0x7D):
            stuffed.append(0x7D)
            stuffed.append(byte ^ 0x20)
        else:
            stuffed.append(byte)
    return bytes(stuffed)

# Character unstuffing
def character_unstuff(data):
    i = 0
    unstuffed = bytearray()
    while i < len(data):
        if data[i] == 0x7D:
            i += 1
            unstuffed.append(data[i] ^ 0x20)
        else:
            unstuffed.append(data[i])
        i += 1
    return bytes(unstuffed)

# Bit error simulation
def simulate_bit_errors(data, error_rate_percent):
    corrupted = bytearray(data)
    num_bits = len(data) * 8
    num_errors = int((error_rate_percent / 100.0) * num_bits)
    for _ in range(num_errors):
        bit_index = random.randint(0, num_bits - 1)
        byte_index = bit_index // 8
        bit_in_byte = bit_index % 8
        corrupted[byte_index] ^= 1 << bit_in_byte
    return bytes(corrupted)

# TCP Tahoe simulation
def simulate_tcp_on_data(total_packets, ssthresh_init, loss_packets):
    cwnd = 1
    ssthresh = ssthresh_init
    state = 'Slow Start'

    time_series = []
    cwnd_series = []
    ssth
