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
    ssthresh_series = []
    state_series = []

    i = 0
    while i < total_packets:
        time_series.append(i)
        cwnd_series.append(cwnd)
        ssthresh_series.append(ssthresh)
        state_series.append(state)

        if i in loss_packets:
            ssthresh = max(cwnd // 2, 1)
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

    return time_series, cwnd_series, ssthresh_series, state_series

# RIP topology plotting
def plot_rip_graph(rip_table, source=None, target=None):
    G = nx.DiGraph()
    for entry in rip_table:
        G.add_edge(entry['node'], entry['dest'], weight=entry['distance'])

    pos = nx.spring_layout(G)
    labels = nx.get_edge_attributes(G, 'weight')
    fig, ax = plt.subplots()
    nx.draw(G, pos, with_labels=True, node_color='lightblue', node_size=800, ax=ax)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, ax=ax)
    ax.set_title("RIP Routing Topology")
    st.pyplot(fig)

    if source is not None and target is not None:
        try:
            path = nx.dijkstra_path(G, source=source, target=target, weight='weight')
            st.success(f"📦 Shortest path from {source} to {target}: {path}")
        except nx.NetworkXNoPath:
            st.error(f"No path from {source} to {target}")

# Main App
def main():
    st.title("🔐 Encrypted Messenger with RIP, TCP & Bit Error Handling")

    with st.form("input_form"):
        message = st.text_area("Enter message to send")
        mss = st.number_input("Enter MSS (Maximum Segment Size)", min_value=1, value=64)
        ssthresh = st.number_input("Enter initial SSTHRESH", min_value=1, value=8)
        bit_error_rate = st.slider("Bit error rate (%)", 0, 100, 0)
        packet_loss_rate = st.slider("Packet loss rate (%)", 0, 100, 20)

        rip_table = []
        num_nodes = st.number_input("Number of nodes in RIP network", min_value=2, value=3)
        for i in range(num_nodes):
            st.markdown(f"Node {i} routing table")
            num_routes = st.number_input(f"  Number of routes from Node {i}", min_value=1, max_value=10, value=2, key=f"routes_{i}")
            for j in range(num_routes):
                col1, col2, col3 = st.columns(3)
                with col1:
                    dest = st.number_input(f"Dest Node", key=f"dest_{i}_{j}")
                with col2:
                    next_hop = st.number_input(f"Next Hop", key=f"hop_{i}_{j}")
                with col3:
                    dist = st.number_input(f"Distance", key=f"dist_{i}_{j}")
                rip_table.append({'node': i, 'dest': dest, 'next_hop': next_hop, 'distance': dist})

        source_node = st.number_input("Source Node", min_value=0, value=0)
        target_node = st.number_input("Target Node", min_value=0, value=1)

        submitted = st.form_submit_button("Submit & Simulate")

    if submitted:
        key = b"thisisasecretkey"
        encrypted = aes_encrypt(message.encode(), key)
        stuffed = character_stuff(encrypted)

        if bit_error_rate > 0:
            stuffed = simulate_bit_errors(stuffed, bit_error_rate)

        total_packets = (len(stuffed) + mss - 1) // mss
        lost_packets = sorted(random.sample(range(total_packets), int((packet_loss_rate / 100) * total_packets)))

        st.subheader("📦 Encrypted & Stuffed Output")
        st.write(f"Encrypted Length: {len(encrypted)} bytes")
        st.code(encrypted.hex())
        st.write(f"Stuffed Length: {len(stuffed)} bytes")
        st.code(stuffed.hex())
        st.write(f"Total Packets: {total_packets}")
        st.write(f"Lost Packets: {lost_packets}")

        st.subheader("📈 TCP Simulation (Tahoe)")
        time_series, cwnd_series, ssthresh_series, states = simulate_tcp_on_data(total_packets, ssthresh, lost_packets)

        for t, c, s, state in zip(time_series, cwnd_series, ssthresh_series, states):
            st.text(f"Time: {t} | CWND: {c} | SSTHRESH: {s} | State: {state}")
            time.sleep(0.05)

        st.subheader("🗺️ RIP Routing")
        plot_rip_graph(rip_table, source_node, target_node)

        st.subheader("📬 Receiver Side")
        try:
            recovered = character_unstuff(stuffed)
            decrypted = aes_decrypt(recovered, key)
            st.success("Recovered Message:")
            st.code(decrypted.decode(errors='ignore'))
        except Exception as e:
            st.error(f"Decryption failed: {e}")

if __name__ == "__main__":
    main()
