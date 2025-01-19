# Basics

### Required tooling must haves
- IEEE 802.11ac or IEEE 802.11ax support
- Supports at least monitor mode and packet injection


### WEP (Wired Equivalent Privacy)
- The original WiFi security protocol, WEP, provides basic encryption but is now considered outdated and insecure due to vulnerabilities that make it easy to breach.
### WPA (WiFi Protected Access)
- Introduced as an interim improvement over WEP, WPA offers better encryption through TKIP (Temporal Key Integrity Protocol), but it is still less secure than newer standards.
### WPA2 (WiFi Protected Access II)
- A significant advancement over WPA, WPA2 uses AES (Advanced Encryption Standard) for robust security. It has been the standard for many years, providing strong protection for most networks.
### WPA3 (WiFi Protected Access III)
- The latest standard, WPA3, enhances security with features like individualized data encryption and more robust password-based authentication, making it the most secure option currently available.

## 4 components -
1. **Evaluating Passphrases:** This involves assessing the strength and security of WiFi network passwords or passphrases. Pentesters employ various techniques, such as dictionary attacks, brute force attacks, and password cracking tools, to evaluate the resilience of passphrases against unauthorized access.

2. **Evaluating Configuration:** Pentesters analyze the configuration settings of WiFi routers and access points to identify potential security vulnerabilities. This includes scrutinizing encryption protocols, authentication methods, network segmentation, and other configuration parameters to ensure they adhere to best security practices.

3. **Testing the Infrastructure:** This phase focuses on probing the robustness of the WiFi network infrastructure. Pentesters conduct comprehensive assessments to uncover weaknesses in network architecture, device configurations, firmware versions, and implementation flaws that could be exploited by attackers to compromise the network.

4. **Testing the Clients:** Pentesters evaluate the security posture of WiFi clients, such as laptops, smartphones, and IoT devices, that connect to the network. This involves testing for vulnerabilities in client software, operating systems, wireless drivers, and network stack implementations to identify potential entry points for attackers.


## The Connection Cycle
Beacon -> Probe Request + Response -> Authentication Request and Response -> Association Request and Response -> Some form of handshake or other security mechanism -> Disassociation/Deauthentication

- Beacon frames from the access point can be identified using the following Wireshark filter - `(wlan.fc.type == 0) && (wlan.fc.type_subtype == 8)`
- Probe request frames from the access point can be identified using the following Wireshark filter - `(wlan.fc.type == 0) && (wlan.fc.type_subtype == 4)`
- The authentication process between the client and the access point can be observed using the following Wireshark filter - `(wlan.fc.type == 0) && (wlan.fc.type_subtype == 11)`
- After the authentication process is complete, the station's association request can be viewed using the following Wireshark filter - `(wlan.fc.type == 0) && (wlan.fc.type_subtype == 0)`
- The access point's association response can be viewed using the following Wireshark filter - `(wlan.fc.type == 0) && (wlan.fc.type_subtype == 1)`
- If the example network uses WPA2, the EAPOL (handshake) frames can be viewed using the following Wireshark filter - `eapol`
- Once the connection process is complete, the termination of the connection can be viewed by identifying which party (client or access point) initiated the disconnection. This can be done using the following Wireshark filter to capture Disassociation frames (10) or Deauthentication frames (12) - `(wlan.fc.type == 0) && (wlan.fc.type_subtype == 12) or (wlan.fc.type_subtype == 10)`

- Display wireless network interface setings and config - `iwconfig`
- Check Current Regulatory Domain, allowed frequencies, power limits and whether the System is using a Global or Country-Specific Regulatory Domain - `iw reg get` (Most of the time, this might be DFS-UNSET, which is not helpful for us since it limits our cards to 20 dBm)
- Changing the Region Settings for our Interface (careful here) - `sudo iw reg set US` (Run `iw reg get` again to confirm)
- Change txpower - ```sudo ifconfig <interface> down
sudo iwconfig <interface> txpower 30
sudo ifconfig <interface> up``` (Kernel may prevent such modifications)

Checking Driver Capabilities of our Interface - `iw list`
Scanning Available WiFi Networks - `iwlist <interface> scan |  grep 'Cell\|Quality\|ESSID\|IEEE'` (Can be very verbose so grepping might be necessary)`
See all available channels for the wireless interface - 
- 


