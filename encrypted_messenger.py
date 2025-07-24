import streamlit as st
from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import random
import time

# AES encryption with detailed visualization for first block
def aes_encrypt_visual(data, key):
    st.subheader("🔐 AES Encryption Formula Used")
    st.latex(r"\text{EncryptedBlock} = \text{AES}_{\text{Encrypt}}(\text{Key}, \text{Block})")
    st.caption("Using AES in ECB mode. Each 16-byte block is encrypted separately.")

    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    encrypted_blocks = []

    for i, block in enumerate(blocks):
        if i == 0:
            st.subheader("🔍 AES Block 1 Encryption (Step-by-Step)")
            for j, byte in enumerate(block):
                st.write(f"Byte {j}: {chr(byte)} (0x{byte:02x})")
            st.write(f"Encrypting with key: {key}")
        encrypted = cipher.encrypt(block)
        encrypted_blocks.append(encrypted)
        if i == 0:
            st.code(f"Block 1 Encrypted: {encrypted.hex()}")
        else:
            st.write(f"Block {i+1} Encrypted: {encrypted.hex()}")

    return b''.join(encrypted_blocks)

# AES decryption
def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    if len(ciphertext) % 16 != 0:
        ciphertext = ciphertext[:len(ciphertext) - (len(ciphertext) % 16)]
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# Character stuffing
def character_stuff(data):
    stuffed = bytearray()
    for byte in data:
        if byte == 0x7E:
            stuffed.append(0x7D)
            stuffed.append(byte ^ 0x20)
        elif byte == 0x7D:
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
    ssthresh_series = []
    ack_series = []
    state_series = []

    time = 0
    i = 0
    while i < total_packets:
        time_series.append(time)
        cwnd_series.append(cwnd)
        ssthresh_series.append(int(ssthresh))
        state_series.append(state)
        ack_series.append(i)

        if i in loss_packets:
            ssthresh = max(cwnd / 2, 1)
            cwnd = 1
            state = 'Slow Start'
        else:
            if state == 'Slow Start':
                cwnd *= 2
                if cwnd >= ssthresh:
                    state = 'Congestion Avoidance'
            elif state == 'Congestion Avoidance':
                cwnd += 1

        i += 1
        time += 1

    return time_series, cwnd_series, ssthresh_series, ack_series, state_series

# RIP routing graph
def plot_rip_graph(rip_table, source=None, target=None):
    G = nx.DiGraph()
    for entry in rip_table:
        G.add_edge(entry['node'], entry['dest'], weight=entry['distance'])

    pos = nx.spring_layout(G, seed=42)
    labels = nx.get_edge_attributes(G, 'weight')

    fig, ax = plt.subplots()
    nx.draw(G, pos, with_labels=True, node_color='lightblue', node_size=700, ax=ax)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, ax=ax)
    st.pyplot(fig)

    if source is not None and target is not None:
        try:
            path = nx.dijkstra_path(G, source=source, target=target, weight='weight')
            st.success(f"📡 Shortest path from {source} to {target}: {path}")
        except:
            st.error("❌ No path found!")

# Plot TCP graphs
def plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, state_series):
    chart = st.empty()
    for i in range(1, len(time_series) + 1):
        fig, ax = plt.subplots(2, 1, figsize=(10, 6))
        ax[0].step(time_series[:i], cwnd_series[:i], where='post', label='CWND', linewidth=2)
        ax[0].step(time_series[:i], ssthresh_series[:i], where='post', linestyle='--', label='SSTHRESH')
        ax[0].legend()
        ax[0].set_title("TCP CWND & SSTHRESH over Time")
        ax[0].grid()

        ax[1].plot(ack_series[:i], cwnd_series[:i], marker='o', linestyle='-', label='ACK')
        ax[1].grid()
        ax[1].set_title("ACKs and CWND")

        chart.pyplot(fig)
        time.sleep(0.3)

# Streamlit GUI
def main():
    st.title("🔐 Encrypted Messenger with Network Simulation")

    role = st.radio("Choose your role", ["Sender", "Receiver"])

    key = b"thisisasecretkey"
    session = st.session_state

    if role == "Sender":
        uploaded_file = st.file_uploader("Upload a text file to send", type=["txt"])
        if uploaded_file:
            raw_data = uploaded_file.read().strip()
            st.text_area("Message to send:", raw_data.decode(), height=150)

            if st.button("Encrypt and Simulate"):
                encrypted = aes_encrypt_visual(raw_data, key)
                stuffed = character_stuff(encrypted)

                st.write("Stuffed Data (hex):")
                st.code(stuffed.hex())

                packet_size = st.number_input("Packet size (MSS)", min_value=1, value=64)
                total_packets = (len(stuffed) + packet_size - 1) // packet_size

                ssthresh = st.number_input("Initial SSTHRESH", min_value=1, value=8)
                loss_rate = st.slider("Packet Loss (%)", 0, 100, 20)
                loss_packets = sorted(random.sample(range(total_packets), int(loss_rate * total_packets / 100)))
                st.write(f"Lost packets: {loss_packets}")

                # RIP setup
                st.subheader("RIP Table")
                rip_table = []
                num_nodes = st.number_input("Number of nodes", min_value=2, value=3)
                for i in range(num_nodes):
                    with st.expander(f"Node {i} routing entries"):
                        num_routes = st.number_input(f"Routes from node {i}", min_value=1, max_value=10, value=2, key=f"r{i}")
                        for j in range(num_routes):
                            dest = st.number_input(f"Dest", key=f"d{i}{j}")
                            hop = st.number_input(f"Hop", key=f"h{i}{j}")
                            dist = st.number_input(f"Dist", key=f"di{i}{j}")
                            rip_table.append({'node': i, 'dest': dest, 'next_hop': hop, 'distance': dist})

                src = st.number_input("Path: Source Node", min_value=0, value=0)
                dst = st.number_input("Path: Destination Node", min_value=0, value=1)
                plot_rip_graph(rip_table, source=src, target=dst)

                t, cwnd, ssthreshs, acks, states = simulate_tcp_on_data(total_packets, ssthresh, loss_packets)
                plot_graphs(t, cwnd, ssthreshs, acks, states)

                # Save to session
                session.stuffed_data = stuffed
                st.success("Data encrypted, stuffed, and simulated successfully! Switch to 'Receiver' to view result.")

    elif role == "Receiver":
        if hasattr(session, 'stuffed_data'):
            st.subheader("Received Stuffed Data (hex):")
            st.code(session.stuffed_data.hex())

            error_rate = st.slider("Bit Error Rate (%)", 0, 100, 0)
            data_to_process = session.stuffed_data
            if error_rate > 0:
                data_to_process = simulate_bit_errors(data_to_process, error_rate)
                st.warning("Bit errors simulated!")

            try:
                unstuffed = character_unstuff(data_to_process)
                decrypted = aes_decrypt(unstuffed, key)
                st.subheader("📬 Decrypted Message:")
                st.code(decrypted.decode(errors="ignore"))
            except Exception as e:
                st.error(f"❌ Decryption error: {str(e)}")
        else:
            st.info("No data received yet. Please wait for sender to encrypt and simulate.")

if __name__ == "__main__":
    main()
