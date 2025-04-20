#!/usr/bin/python3
import requests
import json
import logging
import sys
import getopt
import os
from urllib.parse import urljoin, urlparse
import re
from tqdm import tqdm
import unicodedata

logging.basicConfig()
logging.root.setLevel(logging.INFO)


def slugify(string):
    """
    Slugify a Unicode string, keeping non-ASCII characters (e.g. Arabic).
    
    Example:
        >>> slugify("سلام دنیا")
        'سلام-دنیا'
    """
    # Normalize to decompose diacritics (where possible)
    normalized = unicodedata.normalize('NFKC', string)
    
    # Remove unwanted punctuation (except hyphens and whitespace)
    cleaned = re.sub(r'[^\w\s-]', '', normalized, flags=re.UNICODE)

    # Replace multiple spaces/hyphens with single hyphen
    slug = re.sub(r'[-\s]+', '-', cleaned).strip('-').lower()

    return slug


def main(argv):
    options = ('python download.py\n'
               '-u (CTF URL)\n'
               '-n (CTF name)\n'
               '-o (CTF output directory)\n'
               '-t (API token) OR -c (Cookie: session=?)\n\n'
               'e.g python download.py -u http://ctf.url -n ctf_name -o /home/user/Desktop/ -t api_token')
    try:
        opts, _ = getopt.getopt(argv, 'hu:n:o:t:c:', ['help', 'url=', 'name=', 'output=', 'token=', 'cookie='])
    except getopt.GetoptError:
        print('python download.py -h')
        sys.exit(2)

    if len(opts) < 4:
        print(options)
        sys.exit()

    if any(opt in dict(opts) for opt in ('-h', '--help')):
        print(options)
        sys.exit()
    else:
        baseUrl, ctfName, outputDir = "", "", ""
        headers = {"Content-Type": "application/json"}
        for opt, arg in opts:
            if opt in ('-u', '--url'):
                baseUrl = arg
            if opt in ('-n', '--name'):
                ctfName = arg
            if opt in ('-o', '--output'):
                outputDir = arg
            if opt in ('-t', '--token'):
                headers["Authorization"] = f"Token {arg}"
            elif opt in ('-c', '--cookie'):
                headers["Cookie"] = f"session={arg}"

        os.makedirs(outputDir, exist_ok=True)
        for d in ["challenges", "images"]:
            os.makedirs(os.path.join(outputDir, d), exist_ok=True)

        apiUrl = urljoin(baseUrl, '/api/v1')
        logging.info("Connecting to API: %s" % apiUrl)

        S = requests.Session()
        X = S.get(f"{apiUrl}/challenges", headers=headers).text
        challs = json.loads(X)

        categories = {}

        try:
            logging.info("Retrieved %d challenges..." % len(challs['data']))
        except:
            logging.fatal(challs)
            exit()

        desc_links = []

        for chall in challs['data']:
            Y = json.loads(S.get(f"{apiUrl}/challenges/{chall['id']}", headers=headers).text)["data"]

            if Y["category"] not in categories:
                categories[Y["category"]] = [Y]
            else:
                categories[Y["category"]].append(Y)

            print(slugify(Y["name"]))
            catDir = os.path.join(outputDir, "challenges", Y["category"])
            challDir = os.path.join(catDir, slugify(Y["name"]))

            os.makedirs(catDir, exist_ok=True)
            os.makedirs(challDir, exist_ok=True)

            with open(os.path.join(challDir, "README.md"), "w", encoding="utf-8") as chall_readme:
                logging.info("Creating challenge readme: %s" % Y["name"])
                chall_readme.write(f"# {Y['name']}\n\n")
                chall_readme.write(f"## Description\n\n{Y['description']}\n\n")

                files_header = False

                links = re.findall(r'(https?://[^\s]+)', Y["description"])
                if len(links) > 0:
                    for link in links:
                        desc_links.append((Y["name"], link))

                md_links = re.findall(r'!\[(.*)\]\(([^\s]+)\)', Y["description"])
                if len(md_links) > 0:
                    for link_desc, link in md_links:
                        dl_url = urljoin(baseUrl, link)
                        F = S.get(dl_url, stream=True)
                        fname = urlparse(dl_url).path.split("/")[-1]

                        if link[0] in ["/", "\\"]:
                            link = link[1:]

                        local_f_path = os.path.join(outputDir, link)
                        os.makedirs(os.path.dirname(local_f_path), exist_ok=True)

                        total_size_in_bytes = int(F.headers.get('content-length', 0))
                        progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=fname)

                        with open(local_f_path, "wb") as LF:
                            for chunk in F.iter_content(chunk_size=1024):
                                if chunk:
                                    progress_bar.update(len(chunk))
                                    LF.write(chunk)

                        progress_bar.close()

                if "files" in Y and len(Y["files"]) > 0:
                    if not files_header:
                        chall_readme.write("## Files\n\n")
                        files_header = True

                    challFiles = os.path.join(challDir, "files")
                    os.makedirs(challFiles, exist_ok=True)

                    for file in Y["files"]:
                        f_url = urljoin(baseUrl, file)
                        F = S.get(f_url, stream=True)

                        fname = urlparse(f_url).path.split("/")[-1]
                        local_f_path = os.path.join(challFiles, fname)

                        chall_readme.write(f"* [{fname}](<files/{fname}>)\n\n")

                        total_size_in_bytes = int(F.headers.get('content-length', 0))
                        progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=fname)

                        with open(local_f_path, "wb") as LF:
                            for chunk in F.iter_content(chunk_size=1024):
                                if chunk:
                                    progress_bar.update(len(chunk))
                                    LF.write(chunk)

                        progress_bar.close()

        with open(os.path.join(outputDir, "README.md"), "w", encoding="utf-8") as ctf_readme:
            logging.info("Writing main CTF readme...")

            ctf_readme.write(f"# {ctfName}\n\n")
            ctf_readme.write("## About\n\n[insert description here]\n\n")
            ctf_readme.write("## Challenges\n\n")

            for category in categories:
                ctf_readme.write(f"### {category}\n\n")
                for chall in categories[category]:
                    chall_path = f"challenges/{chall['category']}/{slugify(chall['name'])}/"
                    ctf_readme.write(f"* [{chall['name']}](<{chall_path}>)")

                    if "tags" in chall and len(chall["tags"]) > 0:
                        ctf_readme.write(f" <em>({','.join(chall['tags'])})</em>")

                    ctf_readme.write("\n")

        logging.info("All done!")

        if len(desc_links) > 0:
            logging.warning("** Warning, the following links were found in challenge descriptions, you may need to download these files manually.")
            for cname, link in desc_links:
                logging.warning("%s - %s" % (cname, link))


if __name__ == "__main__":
    main(sys.argv[1:])
