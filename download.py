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

logging.basicConfig()
logging.root.setLevel(logging.INFO)


def slugify(text):
    text = re.sub(r"[\s]+", "-", text.lower())
    text = re.sub(r"[-]{2,}", "-", text)
    text = re.sub(r"[^a-z0-9\-]", "", text)
    text = re.sub(r"^-|-$", "", text)
    return text

def _get_args():
    parser = argparse.ArgumentParser(
      prog='CTFd Download Tool',
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=textwrap.dedent('''\
        Extra Information:
            This tool can be used to download CTFd instances, particularly for generating writeups.
        Example Usage:
            python download.py -u http://myctf.ctfd.io/ -n MyCTF -o /tmp/myctf-writeups -t api_token
         '''))
    parser.add_argument("-u", "--url", help="CTF Base URL (http://myctf.ctfd.io/)", required=True)
    parser.add_argument("-n", "--name", help="CTF Name (MyCTF)", required=True)
    parser.add_argument("-t", "-c", "-s", "--session", help="API Token or Session Cookie (cookie format session=<SESSION_TOKEN>)", required=True)
    parser.add_argument("-o", "--output", help="Output Directory", required=True)
    parser.add_argument("--update", help="Only pull challenges that don't currently have a directory in your repository", action="store_true")
    return parser.parse_args()


def main():
    args = _get_args()
    headers = {"Content-Type": "application/json"}
    baseUrl = args.url
    ctfName = args.name
    outputDir = args.output
    if args.session.startswith("session="):
        headers["Cookie"] = args.session
    else:
        headers["Authorization"] = args.session
    
    # Add the API endpoint to the baseURL
    apiUrl = urljoin(baseUrl, '/api/v1')

    # Make the output directory
    os.makedirs(outputDir, exist_ok=True)

    # Make directories for challenges and images
    for d in ["challenges", "images"]:
        os.makedirs(os.path.join(outputDir, d), exist_ok=True)

    logging.info("Connecting to API: %s" % apiUrl)

    S = requests.Session()
    X = S.get(f"{apiUrl}/challenges", headers=headers).text

    challenges = json.loads(X)

    # Verify that we actually got a list of challenges
    try:
        logging.info("Retrieved %d challenges..." % len(challenges['data']))
    except:
        logging.fatal(challenges)
        exit()

    categories = {}
    desc_links = []

    for chall in challenges['data']:

        Y = json.loads(S.get(f"{apiUrl}/challenges/{chall['id']}", headers=headers).text)["data"]

        if Y["category"] not in categories:
            categories[Y["category"]] = [Y]
        else:
            categories[Y["category"]].append(Y)

        catDir = os.path.join(outputDir, "challenges", Y["category"])
        challDir = os.path.join(catDir, slugify(Y["name"]))

        os.makedirs(catDir, exist_ok=True)
        if not args.update:
            os.makedirs(challDir, exist_ok=True)
        else:
            try:
                os.makedirs(challDir)
            except FileExistsError:
                logging.warning("Skipping download for %s" % challDir)
                continue

        with open(os.path.join(challDir, "README.md"), "w") as chall_readme:
            logging.info("Creating challenge readme: %s" % Y["name"])
            chall_readme.write("# %s\n\n" % Y["name"])
            chall_readme.write("## Description\n\n%s\n\n" % Y["description"])

            files_header = False

            # Find links in description
            links = re.findall(r'(https?://[^\s]+)', Y["description"])

            if len(links) > 0:
                for link in links:
                    desc_links.append((Y["name"], link))

            # Find MD images in description
            md_links = re.findall(r'!\[(.*)\]\(([^\s]+)\)', Y["description"])

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
                    progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=fname)

                    with open(local_f_path, "wb") as LF:
                        for chunk in F.iter_content(chunk_size=1024):
                            if chunk:
                                progress_bar.update(len(chunk))
                                LF.write(chunk)
                        LF.close()

                    progress_bar.close()

            if "files" in Y and len(Y["files"]) > 0:

                if not files_header:
                    chall_readme.write("## Files\n\n")

                challFiles = os.path.join(challDir, "files")
                os.makedirs(challFiles, exist_ok=True)

                for file in Y["files"]:

                    # Fetch file from remote server
                    f_url = urljoin(baseUrl, file)
                    F = S.get(f_url, stream=True)

                    fname = urlparse(f_url).path.split("/")[-1]
                    local_f_path = os.path.join(challFiles, fname)

                    chall_readme.write("* [%s](<files/%s>)\n\n" % (fname, fname))

                    total_size_in_bytes = int(F.headers.get('content-length', 0))
                    progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=fname)

                    with open(local_f_path, "wb") as LF:
                        for chunk in F.iter_content(chunk_size=1024):
                            if chunk:
                                progress_bar.update(len(chunk))
                                LF.write(chunk)
                        LF.close()

                    progress_bar.close()

            chall_readme.close()

    with open(os.path.join(outputDir, "README.md"), "w") as ctf_readme:

        logging.info("Writing main CTF readme...")

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

    logging.info("All done!")

    if len(desc_links) > 0:
        logging.warning("** Warning, the following links were found in challenge descriptions, you may need to download these files manually.")
        for cname, link in desc_links:
            logging.warning("%s - %s" % (cname, link))


if __name__ == "__main__":
    main()
