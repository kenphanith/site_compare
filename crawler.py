import re
import logging
import asyncio
import config
import base64
import os
import mimetypes
import concurrent.futures

from copy import copy
from urllib.parse import urlsplit, urlunsplit, urlparse, urljoin
from urllib.robotparser import RobotFileParser
from urllib.request import Request, urlopen
from datetime import datetime

class IllegalArgumentError(ValueError):
    pass

class Crawler:
    MAX_URLS_PER_SITEMAP = 50000

    # variables
    parserobots = False
    output = None
    report = False

    config = None
    domain = ""

    exclude = []
    skipext = []
    drop    = []

    debug = False
    auth  = False

    urls_to_crawl = set([])
    url_strings_to_output = []
    crawled_or_crawling = set([])
    excluded = set([])

    marked = {}

    not_parsable_resources = (".epub", ".mobi", ".docx", ".doc", ".opf", ".7z", ".ibooks", ".cbr", ".avi", ".mkv", ".mp4", ".jpg", ".jpeg", ".png", ".gif" ,".pdf", ".iso", ".rar", ".tar", ".tgz", ".zip", ".dmg", ".exe")

    # TODO also search for window.location={.*?}
    linkregex = re.compile(b'<a [^>]*href=[\'|"](.*?)[\'"][^>]*?>')
    imageregex = re.compile(b'<img [^>]*src=[\'|"](.*?)[\'"].*?>')

    rp = None
    response_code = {}
    nb_url=1 # number of url
    nb_rp=0 # number of url blocked by the robots.txt
    nb_exclude=0 # number of url excluded by extension or word

    output_file = None

    target_domain = ""
    scheme        = ""

    # Note: some argument here are parsed from config.json
    def __init__(self, num_workers=1, parserobots=False, output=None, report=False, domain="", exclude=[], skipext=[], drop=[],
                 debug=False, verbose=False, images=False, auth=False, as_index=False):
        self.num_workers=num_workers
        self.parserobots=parserobots
        self.output=output
        self.report=report
        self.domain=domain
        self.exclude=exclude
        self.skipext=skipext
        self.drop=drop
        self.debug=debug
        self.verbose=verbose
        self.images=images
        self.auth=auth
        self.as_index=as_index

        if self.debug:
            log_level = logging.DEBUG
        elif self.verbose:
            log_level = logging.INFO
        else:
            log_level = logging.ERROR

        logging.basicConfig(level=log_level)

        self.urls_to_crawl = {self.clean_link(domain)}
        self.url_strings_to_output = []
        self.num_crawled = 0

        if num_workers <= 0:
            raise IllegalArgumentError("Number or workers must be positive")

        try:
            url_parsed = urlparse(domain)
            self.target_domain = url_parsed.netloc
            self.scheme = url_parsed.scheme
        except:
            logging.error("Invalid domain")
            raise IllegalArgumentError("Invalid domain")

        if self.output:
            try:
                self.output_file = open(self.output, 'w')
            except:
                logging.error("Output file not available")
                exit(255)
        # TODO: tobe confirm
        elif self.as_index:
            logging.error("When specifying an index file as an output option, you must include an output file name")
            exit(255)

    def run(self):
        if self.parserobots:
            self.check_robots()

        logging.info("Start the crawling process")

        if self.num_workers == 1:
            while len(self.urls_to_crawl) != 0:
                current_url = self.urls_to_crawl.pop()
                self.crawled_or_crawling.add(current_url)
                self._crawl(current_url)
        else:
            event_loop = asyncio.get_event_loop()
            try:
                while len(self.urls_to_crawl) != 0:
                    executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.num_workers)
                    event_loop.run_until_complete(self.crawl_all_pending_urls(executor))
            finally:
                event_loop.close()

        logging.info("Crawling has reached end of all found links")


    async def crawl_all_pending_urls(self, executor):
        event_loop = asyncio.get_event_loop()

        crawl_tasks = []
        # TODO: tobe confirm
        # Since the tasks created by `run_in_executor` begin executing immediately,

        # `self.urls_to_crawl` will start to get updated, potentially before the below
        # for loop finishes.  This creates a race condition and if `self.urls_to_crawl`
        # is updated (by `self.__crawl`) before the for loop finishes, it'll raise an
        # error

        urls_to_crawl = copy(self.urls_to_crawl)
        self.urls_to_crawl.clear()
        for url in urls_to_crawl:
            self.crawled_or_crawling.add(url)
            task = event_loop.run_in_executor(executor, self._crawl(), url)
            crawl_tasks.append(task)

        logging.debug('waiting on all crawl tasks to complete')
        await asyncio.wait(crawl_tasks)
        logging.debug('all crawl tasks have completed nicely')
        return

    def _crawl(self, current_url):
        url = urlparse(current_url)
        logging.info("Crawling #{}: {}".format(self.num_crawled, url.geturl()))
        self.num_crawled += 1

        request = Request(current_url, headers={"User-Agent": config.crawler_user_agent})

        if self.auth:
            base64string = base64.b64encode(bytes(f'{config.username}:{config.password}', 'ascii'))
            request.add_header("Authorization", "Basic %s" % base64string.decode('utf-8'))

        # Ignore resources listed in the not_parseable_resources
        # to avoid downloading file like pdf... etc
        if not url.path.endswith(self.not_parsable_resources):
            try:
                response = urlopen(request)
            except Exception as e:
                if hasattr(e, 'code'):
                    if e.code in self.response_code:
                        self.response_code[e.code]+=1
                    else:
                        self.marked[e.code] = [current_url]

                    # TODO: tobe confirm
                    if self.report:
                        if e.code in self.marked:
                            self.marked[e.code].append(current_url)
                        else:
                            self.marked[e.code] = [current_url]

                logging.debug("{1} ==> {0}".format(e, current_url))
                return
        else:
            logging.debug("Ignore {0} content might be not parsable.".format(current_url))
            response = None

        # read the response
        if response is not None:
            try:
                msg = response.read()
                if response.getcode() in self.response_code:
                    self.response_code[response.getcode()] += 1
                else:
                    self.response_code[response.getcode()] = 1

                response.close()
            except Exception as e:
                logging.debug("{1} ===> {0}".format(e, current_url))
                return
        else:
            # response is None, content not downloaded, just continue and add the link to sitemap
            msg = "".encode()

        url_string = self.htmlspecialchars(url.geturl())
        print(url_string)
        self.url_strings_to_output.append(url_string)

        # Found links
        links = self.linkregex.findall(msg)

        for link in links:
            link = link.decode("utf-8", errors="ignore")
            logging.debug("Found : {0}".format(link))

            print(link)

            # link in the same url
            if link.startswith('/'):
                link = url.scheme + '://' + url[1] + link

            # anchor link
            elif link.startswith('#'):
                link = url.scheme + '://' + url[1] + url[2] + link

            # ignore
            elif link.startswith(("mailto", "tel")):
                continue

            elif not link.startswith(('http', "https")):
                link = self.clean_link(urljoin(current_url, link))

            # remove the anchor part if needed
            if "#" in link:
                link = link[:link.index('#')]

            # drop attributes if needed
            for toDrop in self.drop:
                link = re.sub(toDrop, '', link)

            # parse the url to get domain and file extension
            parsed_link = urlparse(link)
            domain_link = parsed_link.netloc
            target_extension = os.path.splitext(parsed_link.path)[1][1:]

            if link in self.crawled_or_crawling:
                continue

            if link in self.urls_to_crawl:
                continue

            if link in self.excluded:
                continue

            if domain_link != self.target_domain:
                continue

            if parsed_link.path in ["", "/"] and parsed_link.query == '':
                continue

            if "javascript" in link:
                continue

            if self.is_image(parsed_link.path):
                continue

            if parsed_link.path.startswith("data:"):
                continue

            # Count one more URL
            self.nb_url += 1

            # check if the navigation is allowed by the robots.txt
            if not self.can_fetch(link):
                self.exclude_link(link)
                self.nb_rp += 1
                continue

            # check if the current file extension is allowed or not.
            if target_extension in self.skipext:
                self.exclude_link(link)
                self.nb_exclude += 1
                continue

            # check if the current url doesn't contain an excluded word
            if not self.exclude_url(link):
                self.exclude_link(link)
                self.nb_exclude += 1
                continue

            self.urls_to_crawl.add(link)

    def can_fetch(self, link):
        try:
            if self.parserobots:
                if self.rp.can_fetch("*", link):
                    return True
                else:
                    logging.debug("Crawling of {0} disabled by robots.txt".format(link))
                    return False

            if not self.parserobots:
                return True

            return True

        except:
            # on error continue
            logging.debug("Error during parsing robotx.txt")
            return True

    @staticmethod
    def is_image(path):
        mt,me = mimetypes.guess_type(path)
        return mt is not None and mt.startswith("image/")

    def exclude_link(self, link):
        if link not in self.excluded:
            self.excluded.add(link)

    def exclude_url(self, link):
        for ex in self.exclude:
            if ex in link:
                return False
        return True

    @staticmethod
    def htmlspecialchars(text):
        return text.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")

    def check_robots(self):
        robots_url = urljoin(self.domain, "robots.txt")
        self.rp = RobotFileParser()
        self.rp.set_url(robots_url)
        self.rp.read()

    def clean_link(self, link):
        parts = list(urlsplit(link))
        parts[2] = self.resolve_url_path(parts[2])
        return urlunsplit(parts)

    def resolve_url_path(self, path):
        # From https://stackoverflow.com/questions/4317242/python-how-to-resolve-urls-containing/40536115#40536115
        segments = path.split('/')
        segments = [segment + '/' for segment in segments[:-1]] + [segments[-1]]
        resolved = []
        for segment in segments:
            if segment in ('../', '..'):
                if resolved[1:]:
                    resolved.pop()
            elif segment not in ('./', '.'):
                resolved.append(segment)
        return ''.join(resolved)
