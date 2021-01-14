import argparse
import crawler

# parse arguments
parser = argparse.ArgumentParser(description="site_compare crawler")
group = parser.add_mutually_exclusive_group()
# group.add_argument('--config', action="store", default=None, help="Config json file")
group.add_argument('--domain', action="store", default="", help="Target domain")

arg = parser.parse_args()

dict_arg = arg.__dict__

# TODO: maybe config is not needed (check later)
if dict_arg["domain"] == "":
    print("domain is required")
    exit(0)

crawl = crawler.Crawler(**dict_arg)
crawl.run()