import argparse
from scapy.all import rdpcap, Ether, IP
from pyvis.network import Network
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    return packets

def process_packet(packet):
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            return (src_mac, dst_mac, src_ip, dst_ip)
        return (src_mac, dst_mac, None, None)
    return None

def generate_network_map(packets):
    network_graph = Network(height='100%', width='100%', bgcolor='#222222', font_color='white')
    network_graph.barnes_hut(gravity=-8000, central_gravity=0.3, spring_length=200, spring_strength=0.05, damping=0.09)
    
    added_nodes = set()

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_packet, packet) for packet in packets]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                src_mac, dst_mac, src_ip, dst_ip = result

                if src_mac not in added_nodes:
                    network_graph.add_node(src_mac, label=src_mac, title=f'MAC: {src_mac}', color='#ff0000')  # MAC addresses: red
                    added_nodes.add(src_mac)
                if dst_mac not in added_nodes:
                    network_graph.add_node(dst_mac, label=dst_mac, title=f'MAC: {dst_mac}', color='#ff0000')
                    added_nodes.add(dst_mac)
                network_graph.add_edge(src_mac, dst_mac)

                if src_ip and src_ip not in added_nodes:
                    network_graph.add_node(src_ip, label=src_ip, title=f'IP: {src_ip}', color='#00ff00')  # IP addresses: green
                    added_nodes.add(src_ip)
                if dst_ip and dst_ip not in added_nodes:
                    network_graph.add_node(dst_ip, label=dst_ip, title=f'IP: {dst_ip}', color='#00ff00')
                    added_nodes.add(dst_ip)
                if src_ip and dst_ip:
                    network_graph.add_edge(src_ip, dst_ip)

    return network_graph

def save_network_graph(network_graph, output_file):
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Network Graph</title>
        <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css" rel="stylesheet" type="text/css" />
        <style type="text/css">
            body, html {{
                margin: 0;
                padding: 0;
                width: 100%;
                height: 100%;
                overflow: hidden;
            }}
            #mynetwork {{
                width: 100%;
                height: 100%;
                border: 1px solid lightgray;
            }}
        </style>
    </head>
    <body>
    <div id="mynetwork"></div>
    <script type="text/javascript">
        {graph_html}
    </script>
    </body>
    </html>
    """
    try:
        graph_html = network_graph.generate_html()
        with open(output_file, 'w') as file:
            file.write(html_template.format(graph_html=graph_html))
    except Exception as e:
        print(f"An error occurred while saving the network graph: {e}")

def main():
    parser = argparse.ArgumentParser(description="Generate an enhanced network map from a PCAP file")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("output_file", help="Path to the output HTML file")
    args = parser.parse_args()

    packets = parse_pcap(args.pcap_file)
    network_graph = generate_network_map(packets)
    save_network_graph(network_graph, args.output_file)

if __name__ == "__main__":
    main()
