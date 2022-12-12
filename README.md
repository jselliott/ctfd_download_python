# Python CTFd Downloader
A script to download all the challenges and files from the CTFd instance.

### Installation

#### Clone this repo:

    git clone https://github.com/jselliott/ctfd_download_python.git

#### Install requirements:

    pip install -r requirements.txt
    
#### Generate Access Token

In order to interact with the CTFd API, you'll need to create an Access Token. You can do this by browsing to the Settings page under your profile in the top-right corner of the page, then click on the Access Tokens tab. After inputting an expiration date, click on Generate to create a new token.

#### Run The Downloader

    python download.py -u http://ctf.url -n ctf_name -o /home/user/Desktop/ -t access_token
