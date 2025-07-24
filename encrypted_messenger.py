import streamlit as st
import time
import random
import networkx as nx
import matplotlib.pyplot as plt
from Crypto.Cipher import AES

# ========= AES ENCRYPTION =========
def aes_encrypt(data, key):
    pad_len = 16 - len(data) % 16
    data += bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def aes_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# ========= CHARACTER STUFFING =========
def character_stuff(data):
    stuffed = bytearray()
    for byte in data:
        if byte == 0x7E or byte == 0x7D:
            stuffed.append(0x7D)
            stuffed.append(byte ^ 0x20)
        else:
            stuffed.append(byte)
    return bytes(stuffed)

def character_unstuff(data):
    unstuffed = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0x7D:
            i += 1
            unstuffed.append(data[i] ^ 0x20)
        else:
            unstuffed.append(data[i])
        i += 1
    return bytes(unstuffed)

# ========= RIP PATHFINDING =========
def build_routing_graph(rip_table):
    G = nx.DiGraph()
    for entry in rip_table:
        G.add_edge(entry['src'], entry['dst'], weight=entry['cost'])
    return G

def get_shortest_path(graph, src, dst):
    try:
        path = nx.shortest_path(graph, source=src, target=dst, weight='weight')
        return path
    except nx.NetworkXNoPath:
        return None

def draw_graph(graph, path=None):
    pos = nx.spring_layout(graph, seed=42)
    edge_labels = nx.get_edge_attributes(graph, 'weight')
    plt.figure(figsize=(6, 4))
    nx.draw(graph, pos, with_labels=True, node_color='lightblue', node_size=800)
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels)
    if path:
        path_edges = list(zip(path, path[1:]))
        nx.draw_networkx_edges(graph, pos, edgelist=path_edges, edge_color='red', width=2)
    st.pyplot(plt)

# ========= TCP SIMULATION =========
def simulate_tcp(total_packets, ssthresh, loss_packets):
    cwnd = 1
    state = 'Slow Start'
    time_series = []
    cwnd_series = []
    ssthresh_series = []
    state_series = []

    for t in range(total_packets):
        time_series.append(t)
        cwnd_series.append(cwnd)
        ssthresh_series.append(ssthresh)
        state_series.append(state)

        if t in loss_packets:
            ssthresh = max(1, cwnd // 2)
            cwnd = 1
            state = 'Slow Start'
        else:
            if state == 'Slow Start':
                cwnd *= 2
                if cwnd >= ssthresh:
                    state = 'Congestion Avoidance'
            elif state == 'Congestion Avoidance':
                cwnd += 1
    return time_series, cwnd_series, ssthresh_series, state_series

# ========= BIT ERROR SIM =========
def simulate_bit_errors(data, bit_error_rate):
    corrupted = bytearray(data)
    total_bits = len(corrupted) * 8
    error_bits = int((bit_error_rate / 100) * total_bits)
    for _ in range(error_bits):
        bit_index = random.randint(0, total_bits - 1)
        byte_index = bit_index // 8
        bit_offset = bit_index % 8
        corrupted[byte_index] ^= 1 << bit_offset
    return bytes(corrupted)

# ========= STREAMLIT APP =========
def main():
    st.title("🛰️ Encrypted Messenger with RIP-Based Routing")

    role = st.radio("Select Role", ["Sender", "Receiver"])

    if role == "Sender":
        text = st.text_area("Enter message to send")
        mss = st.number_input("Enter MSS (packet size)", value=32, min_value=8)
        ssthresh = st.number_input("Enter initial SSTHRESH", value=16)
        bit_error_rate = st.slider("Bit Error Rate (%)", 0, 100, 5)
        loss_rate = st.slider("Packet Loss Rate (%)", 0, 100, 10)

        key = b"thisisasecretkey"

        if st.button("Send"):
            st.subheader("Step 1: AES Encryption")
            encrypted = aes_encrypt(text.encode(), key)
            st.code(encrypted.hex())

            st.subheader("Step 2: Character Stuffing")
            stuffed = character_stuff(encrypted)
            st.code(stuffed.hex())

            if bit_error_rate > 0:
                st.subheader("Step 3: Simulate Bit Errors")
                stuffed = simulate_bit_errors(stuffed, bit_error_rate)
                st.code(stuffed.hex())

            st.subheader("Step 4: Packetization")
            packets = [stuffed[i:i+mss] for i in range(0, len(stuffed), mss)]
            total_packets = len(packets)
            st.write(f"Total packets: {total_packets}")

            st.subheader("Step 5: TCP Simulation")
            num_losses = int(loss_rate / 100 * total_packets)
            loss_packets = sorted(random.sample(range(total_packets), num_losses))
            t, cwnd, ssthresh_list, state = simulate_tcp(total_packets, ssthresh, loss_packets)
            st.line_chart({"CWND": cwnd, "SSTHRESH": ssthresh_list})

            st.subheader("Step 6: Routing Table")
            num_links = st.number_input("Enter number of links in RIP table", 1, 20, 4)
            rip_table = []
            for i in range(num_links):
                cols = st.columns(3)
                src = cols[0].text_input(f"Link {i+1} - From", value=f"A", key=f"src{i}")
                dst = cols[1].text_input(f"To", value=f"B", key=f"dst{i}")
                cost = cols[2].number_input(f"Cost", min_value=1, value=1, key=f"cost{i}")
                rip_table.append({'src': src, 'dst': dst, 'cost': cost})

            G = build_routing_graph(rip_table)
            src_node = st.text_input("Enter source node", value="A")
            dst_node = st.text_input("Enter destination node", value="B")

            path = get_shortest_path(G, src_node, dst_node)
            draw_graph(G, path)
            if path:
                st.success(f"Message will be sent via path: {path}")
                # Save for receiver
                st.session_state['sent_data'] = {
                    'payload': stuffed,
                    'key': key,
                }

    elif role == "Receiver":
        st.subheader("📥 Waiting for Incoming Data...")
        if 'sent_data' in st.session_state:
            payload = st.session_state['sent_data']['payload']
            key = st.session_state['sent_data']['key']
            st.write("Data received!")

            st.subheader("Unstuffing")
            try:
                unstuffed = character_unstuff(payload)
                st.code(unstuffed.hex())

                st.subheader("Decrypting")
                decrypted = aes_decrypt(unstuffed, key)
                st.success("Decrypted Message:")
                st.code(decrypted.decode(errors='ignore'))
            except Exception as e:
                st.error(f"Error while processing received message: {e}")
        else:
            st.warning("No message has been sent yet.")

if __name__ == "__main__":
    main()
