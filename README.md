### SCRIPT INSTALLATION💡


# copy this command down 👇 and past on the server🚦

```bash
apt update && \
apt install -y curl && \
curl -L -o install.sh "https://raw.githubusercontent.com/btnst-oss/manager/main/install.sh" && chmod +x install.sh && sudo ./install.sh && rm install.sh
```

### SLOW DNS ONLY NO PANEL🪷
For Debian and kali Linux 
```bash
sudo apt update  -y && apt upgrade -y 
sudo apt install -y curl && \
curl -fsSL https://raw.githubusercontent.com/noten28/manage/main/slowdns/mjerumani.sh -o mjerumani.sh && \
chmod +x mjerumani.sh && \
sed -i 's/\r$//' mjerumani.sh && \
./mjerumani.sh
```
