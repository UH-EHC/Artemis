from scrapy import Spider
from scrapy.linkextractors import LinkExtractor
from Artemis.pipelines import ArtemisPipeline
import Artemis.settings as settings
from urllib.parse import urlparse
import sys


class Artemis_spider(Spider):
    name = 'artemis'
    visited_domains = 0
    start_urls = ['https://ethicalhacking.club']

    def parse(self, response):
        le = LinkExtractor()
        for link in le.extract_links(response):
            # termination setting
            if Artemis_spider.visited_domains >= settings.MAX_DOMAINS:
                print("Reached MAX_LIMIT of domains: {}".format(settings.MAX_DOMAINS))
                return
            # STEP 1: get a target
            domain = urlparse(link.url).netloc
            Artemis_spider.visited_domains += 1
            artemis = ArtemisPipeline()
            # STEP 2: check this target
            artemis.process_item(domain)

