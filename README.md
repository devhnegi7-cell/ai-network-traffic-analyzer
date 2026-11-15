# AI-Powered Network Traffic Analyzer

A Streamlit app for summarizing network captures. Upload a Wireshark `.pcap` or `.pcapng` file, or select a local adapter and capture for up to 10 seconds or 5,000 packets. The dashboard shows packet categories, DNS response codes, and NXDOMAIN replies grouped by domain.

Scapy computes the statistics. A local Qwen2.5 model served through Ollama uses those statistics to write an optional plain-English report that can be downloaded as a text file.

## Run locally on Windows

1. Install Python. Install Npcap if you want to use live capture.
2. Open PowerShell in the project folder and run:

   ```powershell
   py -m pip install -r requirements.txt
   py -m streamlit run app.py
   ```

3. To enable AI reports, install Ollama and download the model in a separate terminal:

   ```powershell
   ollama pull qwen2.5:3b
   ```

   Keep the local Ollama service running while generating reports. Packet counts and DNS tables are available independently of Ollama.

## Demo

Select **Live capture**, choose your active Wi-Fi or Ethernet adapter, and start a capture. During the capture, run `nslookup example.invalid` in another terminal. If the DNS reply is visible on the selected adapter, the domain appears under **Failed DNS Lookups**. You can also use **Upload capture** to analyze a saved file.

DNS packets are counted in their own dashboard category, even when carried over UDP or TCP. NXDOMAIN counts represent reply packets, so repeated replies for one domain increase its count.
