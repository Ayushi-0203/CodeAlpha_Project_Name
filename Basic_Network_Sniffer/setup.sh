# create virtual environment in the working directory
sudo apt-get install python3 
python3 -m venv sniffer

# activate the virtual environment
source ./sniffer/bin/activate

# install scapy library 
pip3 install scapy 

# run the python file with root privilige
sudo su
python3 sniffer.py
