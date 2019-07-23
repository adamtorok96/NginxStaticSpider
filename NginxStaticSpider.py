from urllib.parse import urlparse

import requests
import scrapy


class GitSpider(scrapy.Spider):
    name = 'NginxStaticSpider'

    allowed_schemes = [
        'http',
        'https'
    ]

    disallowed_tlds = [
        'com',
        'net'
    ]

    def __init__(self, **kwargs):
        super().__init__(self.name, **kwargs)

        if not hasattr(self, 'url'):
            raise Exception('No url argument provided!')

        starting_url = self.url

        if not starting_url.startswith('http://') and not starting_url.startswith('https://'):
            starting_url = 'https://' + starting_url

        print('Starting url: %s' % starting_url)

        self.start_urls = ['%s' % starting_url]

    def parse(self, response):
        # print('Response URL: %s' % response.url)

        parsed_root_url = urlparse(response.url)

        self.check_for_vulnerability('%s://%s' % (parsed_root_url.scheme, parsed_root_url.netloc), response.headers)

        for url in response.xpath('//a/@href').extract():
            parsed_url = urlparse(url)

            if len(parsed_url.scheme) == 0 or len(parsed_url.netloc) == 0:
                continue

            if parsed_root_url.netloc is parsed_url.netloc:
                continue

            if parsed_url.scheme not in self.allowed_schemes:
                continue

            domain = parsed_url.netloc
            domains = domain.split('.')

            tld = domains[len(domains) - 1]

            if tld in self.disallowed_tlds:
                continue

            if len(domains) != 2:
                domain = '%s.%s' % (domains[len(domains) - 2], domains[len(domains) - 1])

            url = '%s://%s' % (parsed_url.scheme, domain)

            yield scrapy.Request(url, callback=self.parse)

    def check_for_vulnerability(self, url, headers):
        if not self.is_nginx(headers):
            return

        # response = requests.get('%s/static/' % url, verify=False)
        #
        # if response.status_code != 200:
        #     if response.status_code != 404:
        #         print('Response code wrong: %d %s' % (response.status_code, url))
        #     return

        response = requests.get('%s/static../' % url, verify=False)

        if response.status_code == 403:
            print('[+] Possible found: %s' % url)
            self.log_possible_found(url, response)
        # else:
        #     print('[-] Not found: %s' % url)

    @staticmethod
    def log_possible_found(url, response):
        f = open('out/found.txt', 'a+')
        f.write('%s\n' % url)
        f.close()

        filename = 'out/%s' % url.replace(':', '_').replace('//', '')

        f = open(filename, 'w+')
        f.write(response.content.decode('UTF-8'))
        f.close()

    @staticmethod
    def is_nginx(headers):
        server = None

        if 'Server' in headers:
            server = headers['Server']
        elif 'server' in headers:
            server = headers['server']

        # it can be false positive
        if server is None:
            return True

        server = server.decode('utf-8').lower()

        return 'nginx' in server