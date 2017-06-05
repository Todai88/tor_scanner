import argparse
from scanner import Scanner
import os

if __name__ == u'__main__':


    """
    Setting up a basic argparser
    to allow us to use files of our 
    choice
    """

    parser = argparse.ArgumentParser(
        description=u'An Onion Scanner'
    )

    parser.add_argument(
        u'-F',
        dest='onion_file',
        default='onion_master_list.txt',
        help=u'The Path to your list of Onions.'
    )

    arguments = parser.parse_args()

    if not os.path.isfile(arguments.onion_file):
        parser.print_help()
        raise SystemExit

    Scanner(arguments.onion_file)
