from flask import Flask, request, render_template
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
import csv
import numpy as np
import pickle
# Declare a Flask app
app = Flask(__name__)

# Main function here
# ------------------
@app.route('/')
def main():
    return render_template("home.html")

@app.route('/capture_live')
def capture_live():
    return render_template('index.html')

@app.route('/predict_existing')
def predict_existing():
    return render_template('predict_existing.html')

@app.route('/input_pcap')
def input_pcap():
    return render_template('pcap_input.html')

@app.route('/convert_pcap', methods=['GET', 'POST'])
def convert_pcap():
    file = request.files['file']
    packets = rdpcap("captured.pcap")
    # Initialize an empty list to store the features
    # feature_list = ['src_ip', 'dst_ip', 'protocol_type', 'src_port', 'dst_port','srv_count', 'duration',' service', 'flag','src_bytes', 'dst_bytes', \
    #                'wrong_fragment', 'hot', 'num_failed_logins', 'logged_in', 'lnum_compromised', 'root_shell', \
    #                'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', \
    #                'is_hot_login', 'is_guest_login', 'count','diff_srv_rate','same_srv_rate','srv_rerror_rate' ]
    feature_list=['src_bytes', 'count', 'service', 'srv_count', 'protocol_type',\
        'diff_srv_rate', 'same_srv_rate', 'flag', 'dst_bytes',\
        'srv_serror_rate', 'logged_in', 'duration', 'lnum_compromised',\
        'wrong_fragment', 'is_guest_login', 'num_failed_logins']
    features = []
    # Iterate through each packet in the .pcap file
    for packet in packets:
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # flags = packet[TCP].flags
            service = "unassigned"
            urgent = packet[TCP].urgptr
            flag="OTH"

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            flag = "SF"
            service = "unassigned"
        else:
            src_port = ""
            dst_port = ""
            flags = ""
            service = ""
            urgent = ""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_type = packet[IP].proto
            duration = int(packet.time - packets[0].time)
            src_bytes = packet[IP].len
            dst_bytes = packet[IP].len
            wrong_fragment = packet[IP].frag
        # else:
        #     src_ip = ""
        #     dst_ip = ""
        #     protocol = ""
        #     duration = ""
        #     src_bytes = ""
        #     dst_bytes = ""
        #     wrong_fragment = "" 
        hot = 0
        num_failed_logins = 0
        logged_in = 1
        lnum_compromised = 0
        root_shell = 0
        su_attempted = 0
        num_root = 0
        num_file_creations = 0
        num_shells = 0
        num_access_files = 0
        num_outbound_cmds = 0
        is_hot_login = 0
        is_guest_login = 0
        count = 1
        srv_count = 1
        serror_rate = 0
        srv_serror_rate = 0
        rerror_rate = 0
        srv_rerror_rate = 0
        same_srv_rate = 1
        diff_srv_rate = 0
        srv_diff_host_rate = 0
        dst_host_count = 1
        dst_host_srv_count = 1
        dst_host_same_srv_rate = 1
        dst_host_diff_srv_rate = 0
        dst_host_same_src_port_rate = 0
        dst_host_srv_diff_host_rate = 0
        dst_host_serror_rate = 0
        dst_host_srv_serror_rate = 0
        dst_host_rerror_rate = 0
        dst_host_srv_rerror_rate = 0


        # features.append([src_ip, dst_ip, protocol_type, src_port, dst_port,srv_count, int(duration), service, flag,src_bytes, dst_bytes,
        #             wrong_fragment, hot, num_failed_logins, logged_in, lnum_compromised, root_shell,
        #             su_attempted, num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds,
        #             is_hot_login, is_guest_login, count, diff_srv_rate,same_srv_rate,srv_rerror_rate])
        features.append([src_bytes, count, service, srv_count, protocol_type, diff_srv_rate, same_srv_rate,flag,dst_bytes,srv_serror_rate,
                        logged_in, duration, lnum_compromised, wrong_fragment, is_guest_login, num_failed_logins])

    filename = 'converted.csv'

    with open(filename,'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(feature_list)

        for row in features:
            writer.writerow(row)

# for i in features:
#     print(i)
#     print('/n')


    return render_template("pcap_kdd.html")


@app.route('/getcsv')
def getcsv():
    return render_template("CSV_input.html")


#prediction from pre trained model
@app.route('/predict', methods=['GET', 'POST'])
def predict():
    file = request.files['file']
    df = pd.read_csv(file)
    order=['src_bytes', 'count', 'service', 'srv_count', 'protocol_type',
        'diff_srv_rate', 'same_srv_rate', 'flag', 'dst_bytes',
        'srv_serror_rate', 'logged_in', 'duration', 'lnum_compromised',
        'wrong_fragment', 'is_guest_login', 'num_failed_logins']
    
    df=df[(df.columns)&(order)]
    df=df[order]
    
    #categorical variable into numerical variable
    df['protocol_type'] = df['protocol_type'].astype('category')
    df['service'] = df['service'].astype('category')
    df['flag'] = df['flag'].astype('category')
    cat_columns = df.select_dtypes(['category']).columns
    df[cat_columns] = df[cat_columns].apply(lambda x: x.cat.codes)

    # trained_model = pickle.load(open('Trained_Model.sav', 'rb'))
    trained_model = pickle.load(open('Trained_Model.sav', 'rb'))

    data=df.to_numpy()
    #predicting
    predictions_attack = trained_model.predict(data)
    predictions = []
    for i in predictions_attack:
        if i == 0:
            predictions.append('Normal')
        if i == 1:
            predictions.append('DoS')
        if i == 2:
            predictions.append('Probe')
        if i == 3:
            predictions.append('R2L')
        if i == 4:
            predictions.append('U2R')

    return render_template('predictions.html',predictions=predictions)

@app.route('/capture_packets')
def capture_packets():
    def callback(pkt):
        wrpcap("captured.pcap", pkt, append=True)

    sniff(iface="Wi-Fi", prn=callback, count=5)
    return render_template('capture_packets.html')

        
@app.route('/pcap_kdd')
def pcap_kdd():
# Read the .pcap file
    packets = rdpcap("captured.pcap")
    # Initialize an empty list to store the features
    # feature_list = ['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'duration',' service', 'src_bytes', 'dst_bytes', \
    #                'wrong_fragment', 'hot', 'num_failed_logins', 'logged_in', 'lnum_compromised', 'root_shell', \
    #                'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', \
    #                'is_hot_login', 'is_guest_login', 'count' ]
    feature_list=['src_bytes', 'count', 'service', 'srv_count', 'protocol_type',\
        'diff_srv_rate', 'same_srv_rate', 'flag', 'dst_bytes',\
        'srv_serror_rate', 'logged_in', 'duration', 'lnum_compromised',\
        'wrong_fragment', 'is_guest_login', 'num_failed_logins']
    features = []
    # Iterate through each packet in the .pcap file
    for packet in packets:
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # flags = packet[TCP].flags
            service = "unassigned"
            urgent = packet[TCP].urgptr
            flag="OTH"

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            flag = "SF"
            service = "unassigned"
        else:
            src_port = ""
            dst_port = ""
            flags = ""
            service = ""
            urgent = ""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_type = packet[IP].proto
            duration = int(packet.time - packets[0].time)
            src_bytes = packet[IP].len
            dst_bytes = packet[IP].len
            wrong_fragment = packet[IP].frag
        # else:
        #     src_ip = ""
        #     dst_ip = ""
        #     protocol = ""
        #     duration = ""
        #     src_bytes = ""
        #     dst_bytes = ""
        #     wrong_fragment = "" 
        hot = 0
        num_failed_logins = 0
        logged_in = 1
        lnum_compromised = 0
        root_shell = 0
        su_attempted = 0
        num_root = 0
        num_file_creations = 0
        num_shells = 0
        num_access_files = 0
        num_outbound_cmds = 0
        is_hot_login = 0
        is_guest_login = 0
        count = 1
        srv_count = 1
        serror_rate = 0
        srv_serror_rate = 0
        rerror_rate = 0
        srv_rerror_rate = 0
        same_srv_rate = 1
        diff_srv_rate = 0
        srv_diff_host_rate = 0
        dst_host_count = 1
        dst_host_srv_count = 1
        dst_host_same_srv_rate = 1
        dst_host_diff_srv_rate = 0
        dst_host_same_src_port_rate = 0
        dst_host_srv_diff_host_rate = 0
        dst_host_serror_rate = 0
        dst_host_srv_serror_rate = 0
        dst_host_rerror_rate = 0
        dst_host_srv_rerror_rate = 0


        # features.append([src_ip, dst_ip, protocol, src_port, dst_port, int(duration), service, src_bytes, dst_bytes,
        #             wrong_fragment, hot, num_failed_logins, logged_in, lnum_compromised, root_shell,
        #             su_attempted, num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds,
        #             is_hot_login, is_guest_login, count])
        features.append([src_bytes, count, service, srv_count, protocol_type, diff_srv_rate, same_srv_rate,flag,dst_bytes,srv_serror_rate,
                        logged_in, duration, lnum_compromised, wrong_fragment, is_guest_login, num_failed_logins])

    filename = 'Live_captured.csv'

    with open(filename,'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(feature_list)

        for row in features:
            writer.writerow(row)

# for i in features:
#     print(i)
#     print('/n')


    return render_template("pcap_kdd.html")

@app.route('/About')
def About():
    return render_template("About.html")
    

# Running the app
if __name__ == '__main__':
    app.run(debug = True)
