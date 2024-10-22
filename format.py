import argparse
import pathlib
import textwrap

def link_images(writeup_dir, line):
    # TODO implement this
    return line


def _get_args():
    parser = argparse.ArgumentParser(
      prog='Writeup Formatter Tool',
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=textwrap.dedent('''\
        Extra Information:
            Write your solution in individual challenge writeups under a Solution header:
                ## Solution
                Your solution here 
            
            This tool looks for this header in challenge readmes and applies a checkmark 
            to the challenge in the main README.md if it is found.

            If you want to link images in the writeups, use the --link-images flag.
            Images can be linked from the writeup directory using the custom syntax:
                (((image.png)))

            Where image.png is a name of an image in the /images directory of the writeup directory. 
         '''))
    parser.add_argument('writeup_dir', type=str, help='The directory containing the writeups')
    parser.add_argument('--link-images', action="store_true", help='The directory containing the writeups')
    return parser.parse_args()

def main():
    args = _get_args()
    new_readme = []
    main_readme =  pathlib.Path(args.writeup_dir, 'README.md')
    if not main_readme.exists():
        print(f'Error: {main_readme} does not exist')
        return
    with main_readme.open('r') as f:
        main_readme_content = f.readlines()
    
    for line in main_readme_content:
        is_solved = False
        if line.startswith("* "):
            path = line.split('(<')[1].split('>)')[0]
            writeup_path = pathlib.Path(args.writeup_dir, path, "README.md")
            if not writeup_path.exists():
                print(f'Error: {writeup_path} does not exist')
                return
            with writeup_path.open('r') as f:
                writeup_content = f.readlines()
            new_chal_readme = []
            for wline in writeup_content:
                if wline.startswith("## Solution"):
                    is_solved = True
                    break
                if args.link_images:
                    wline = link_images(args.writeup_dir, wline)
                new_chal_readme.append(wline)
            if args.link_images:
                with writeup_path.open('w') as f:
                    f.writelines(new_chal_readme)
                
            if is_solved:
                line = line.replace('* ', '* :white_check_mark: ')
        new_readme.append(line)
    
    with main_readme.open('w') as f:
        f.writelines(new_readme)

if __name__ == '__main__':
    main()
