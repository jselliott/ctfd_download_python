#!/usr/bin/python3
import requests
import json
import logging
import os
from urllib.parse import urljoin, urlparse
import re
from tqdm import tqdm
import argparse
import textwrap
import sys

class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

LOG_COUNT = 0
class ContextFilter(logging.Filter):
    def filter(self, record):
        global LOG_COUNT
        LOG_COUNT += 1
        return True

# create logger 
logger = logging.getLogger("CTFd Downloader")
logger.setLevel(logging.WARNING)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.WARNING)
ch.setFormatter(CustomFormatter())
ch.addFilter(ContextFilter())
logger.addHandler(ch)

def back_n_lines(back=1):
    "Deletes the last line in the STDOUT"
    if back == 0:
        return
    # cursor up n lines
    for _ in range(back):
        sys.stdout.write('\x1b[1A')

def forward_n_lines(forward=1):
    "Moves the cursor down n lines"
    if forward == 0:
        return
    # cursor down n lines
    for _ in range(forward):
        sys.stdout.write('\033[1B')
    sys.stdout.flush()

def clear_line():
    # delete last line
    sys.stdout.write('\x1b[2K')

def slugify(text):
    text = re.sub(r"[\s]+", "-", text.lower())
    text = re.sub(r"[-]{2,}", "-", text)
    text = re.sub(r"[^a-z0-9\-]", "", text)
    text = re.sub(r"^-|-$", "", text)
    return text

def _get_args():
    parser = argparse.ArgumentParser(
      prog='ctf-downloader',
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=textwrap.dedent('''\
        Extra Information:
            This tool can be used to download CTFd instances, particularly for generating writeups.
        Example Usage:
            ctfd-downloader -u http://myctf.ctfd.io/ -n MyCTF -o /tmp/myctf-writeups -t api_token
         '''))
    parser.add_argument("-u", "--url", help="CTF Base URL (http://myctf.ctfd.io/)", required=True)
    parser.add_argument("-n", "--name", help="CTF Name (MyCTF)", required=True)
    parser.add_argument("-t", "-c", "-s", "--session", help="API Token or Session Cookie (cookie format session=<SESSION_TOKEN>)", required=True)
    parser.add_argument("-o", "--output", help="Output Directory", required=True)
    parser.add_argument("--update", help="Only pull challenges that don't currently have a directory in your repository", action="store_true")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    return parser.parse_args()


def main():
    global LOG_COUNT
    args = _get_args()
    print("Starting CTFd Downloader")
    print("URL: %s" % args.url)

    if args.verbose == 1:
        logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)
    elif args.verbose == 2:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)

    headers = {"Content-Type": "application/json"}
    baseUrl = args.url
    ctfName = args.name
    outputDir = args.output
    if args.session.startswith("session="):
        headers["Cookie"] = args.session
    else:
        headers["Authorization"] = f"Bearer {args.session}"
    
    # Add the API endpoint to the baseURL
    apiUrl = urljoin(baseUrl, '/api/v1')

    # Make the output directory
    os.makedirs(outputDir, exist_ok=True)

    # Make directories for challenges and images
    for d in ["challenges", "images"]:
        os.makedirs(os.path.join(outputDir, d), exist_ok=True)

    logger.info("Connecting to API: %s" % apiUrl)

    S = requests.Session()
    X = S.get(f"{apiUrl}/challenges", headers=headers).text

    challenges = json.loads(X)

    # Verify that we actually got a list of challenges
    try:
        logger.info("Retrieved %d challenges..." % len(challenges['data']))
    except:
        logger.fatal(challenges)
        exit()

    categories = {}
    desc_links = []

    for chall in challenges['data']:
        
        # See if we have all the information we need already
        if (
            "category" in chall and "name" in chall and
            "description" in chall and "id" in chall and
            "files" in chall
        ):
            chal_data = chall
        else:
            chal_data = S.get(f"{apiUrl}/challenges/{chall['id']}", headers=headers).text
            try:
                chal_data = json.loads(chal_data)["data"]
            except KeyError:
                logger.error("Error fetching challenge data for %s" % chall['name'])
                continue

        if chal_data["category"] not in categories:
            categories[chal_data["category"]] = [chal_data]
        else:
            categories[chal_data["category"]].append(chal_data)

        catDir = os.path.join(outputDir, "challenges", chal_data["category"])
        challDir = os.path.join(catDir, slugify(chal_data["name"]))

        os.makedirs(catDir, exist_ok=True)
        if not args.update:
            os.makedirs(challDir, exist_ok=True)
        else:
            try:
                os.makedirs(challDir)
            except FileExistsError:
                logger.warning("Skipping download for %s" % challDir)
                continue

        with open(os.path.join(challDir, "README.md"), "w") as chall_readme:
            logger.info("Creating challenge readme: %s" % chal_data["name"])
            chall_readme.write("# %s\n\n" % chal_data["name"])
            chall_readme.write("## Description\n\n%s\n\n" % chal_data["description"])

            files_header = False

            # Find links in description
            links = re.findall(r'(https?://[^\s]+)', chal_data["description"])

            if len(links) > 0:
                for link in links:
                    desc_links.append((chal_data["name"], link))

            # Find MD images in description
            md_links = re.findall(r'!\[(.*)\]\(([^\s]+)\)', chal_data["description"])

            if len(md_links) > 0:
                for link_desc, link in md_links:
                    dl_url = urljoin(baseUrl, link)

                    F = S.get(dl_url, stream=True)

                    fname = urlparse(f_url).path.split("/")[-1]

                    if link[0] in ["/", "\\"]:
                        link = link[1:]

                    local_f_path = os.path.join(outputDir, link)
                    os.makedirs(os.path.join(outputDir, os.path.dirname(link)), exist_ok=True)

                    total_size_in_bytes = int(F.headers.get('content-length', 0))
                    back_n_lines(LOG_COUNT+1)
                    clear_line()
                    progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=fname)

                    with open(local_f_path, "wb") as LF:
                        for chunk in F.iter_content(chunk_size=1024):
                            if chunk:
                                progress_bar.update(len(chunk))
                                LF.write(chunk)
                        LF.close()

                    progress_bar.close()
                    forward_n_lines(LOG_COUNT+1)

            if "files" in chal_data and len(chal_data["files"]) > 0:

                if not files_header:
                    chall_readme.write("## Files\n\n")

                challFiles = os.path.join(challDir, "files")
                os.makedirs(challFiles, exist_ok=True)

                for file in chal_data["files"]:

                    # Fetch file from remote server
                    f_url = urljoin(baseUrl, file)
                    F = S.get(f_url, stream=True)

                    fname = urlparse(f_url).path.split("/")[-1]
                    local_f_path = os.path.join(challFiles, fname)

                    chall_readme.write("* [%s](<files/%s>)\n\n" % (fname, fname))

                    total_size_in_bytes = int(F.headers.get('content-length', 0))
                    back_n_lines(LOG_COUNT+1)
                    progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=fname)

                    with open(local_f_path, "wb") as LF:
                        for chunk in F.iter_content(chunk_size=1024):
                            if chunk:
                                progress_bar.update(len(chunk))
                                LF.write(chunk)
                        LF.close()

                    progress_bar.close()
                    forward_n_lines(LOG_COUNT)

            chall_readme.close()

    with open(os.path.join(outputDir, "README.md"), "w") as ctf_readme:

        logger.info("Writing main CTF readme...")

        ctf_readme.write("# %s\n\n" % ctfName)
        ctf_readme.write("## About\n\n[insert description here]\n\n")
        ctf_readme.write("## Challenges\n\n")

        for category in categories:
            ctf_readme.write("### %s\n\n" % category)

            for chall in categories[category]:

                chall_path = "challenges/%s/%s/" % (chall['category'], slugify(chall['name']))
                ctf_readme.write("* [%s](<%s>)" % (chall['name'], chall_path))

                if "tags" in chall and len(chall["tags"]) > 0:
                    ctf_readme.write(" <em>(%s)</em>" % ",".join(chall["tags"]))

                ctf_readme.write("\n")
            ctf_readme.write("\n")

        ctf_readme.close()

    logger.info("All done!")

    if len(desc_links) > 0:
        logger.warning("** Warning, the following links were found in challenge descriptions, you may need to download these files manually.")
        for cname, link in desc_links:
            logger.warning("%s - %s" % (cname, link))


if __name__ == "__main__":
    main()
