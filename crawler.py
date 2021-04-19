# encoding: utf-8
import hashlib
import json
import re
import time
import traceback
from typing import List

from bloompy import BloomFilter
from playwright.sync_api import sync_playwright, Request, ElementHandle, Route


class Crawler(object):

    def __init__(self, depth: int, max_url_nums: int, cookies: str, exclude_urls: List[str],
                 domain_reg_list: List[str],
                 path_dicts: List[str], header: dict = None):
        """
        :param depth: 爬虫深度，默认是5
        :param max_url_nums: 最大爬取的url数量，默认是5000
        :param cookies: 传入的cookie，直接按：a=b;c=d传入即可
        :param exclude_urls: 不需要爬取的url，也不会出现在结果列表里，同样也可以按以下语法传入模糊匹配参数：*/logout
        :param domain_reg_list: 关于域名校验的表达式，直接传入域名或者根域即可，如：baidu.com,www.baidu.com.cn，只会爬取当前域名下的
        :param path_dicts: 路径字典，暂时没有实现相关功能
        :param header: http头，传入字典
        """
        self.domain_reg = ''
        self.domain_reg_list = domain_reg_list
        self.complement = 0
        self.depth = 5 if not depth else depth
        self.max_url_nums = 5000 if not max_url_nums else max_url_nums
        self.cookie = cookies
        self.exclude_urls = [url.replace('*', '\\S*') for url in exclude_urls]
        self.url_dict = dict()
        self.url_cache = BloomFilter(element_num=max_url_nums * 5, error_rate=0.01)
        self.current_depth = 0
        self.current_crawl_queue = list()
        self.next_crawl_queue = list()
        self.max_queue_length = self.max_url_nums + 1000
        self.header = header
        self.path_dicts = path_dicts
        self.header = header
        self.filter_exts = [
            'css', 'png', 'gif', 'jpg', 'jpeg', 'swf', 'tiff',
            'pdf', 'ico', 'flv', 'mp4', 'mp3', 'avi', 'mpg', 'gz',
            'mpeg', 'iso', 'dat', 'mov', 'rar', 'exe', 'zip', 'tar',
            'bin', 'bz2', 'xsl', 'doc', 'docx', 'ppt', 'pptx', 'xls',
            'xlsx', 'csv', 'map', "ttf", 'tif', 'woff', 'woff2',
            'cab', 'apk', 'bmp', 'svg', 'exif', 'xml', 'rss', 'webp'
        ]
        self.exclude_urls_reg_str = ''

    @staticmethod
    def parse_domain(domain_list):
        """
        需要将输入的url或者域名解析成域名, 用于后续同域判断等操作
        :param domain_list:
        :return:
        """

        def _split_url_protocol_and_path(domain):
            # 去掉协议
            if '://' in domain:
                domain = domain.split('://')[1]
            # 截取路径
            if '.com.cn' in domain:
                return domain.split('.com.cn')[0] + '.com.cn'
            if '.com' in domain:
                return domain.split('.com')[0] + '.com'
            if '.xyz' in domain:
                return domain.split('.xyz')[0] + '.xyz'
            # 针对ip:port形式的url,截取/即可
            return domain.split('/')[0]

        return [_split_url_protocol_and_path(domain) for domain in domain_list]

    def _init_reg(self):
        """
        根据解析出来的域名拼接一个正则, 用于同域校验
        :return:
        """
        domain_reg = ['^']
        domain_reg.extend(['(http|https):\/\/' + domain.replace('.', '\.') + '.*|' for domain in self.domain_reg_list])
        # domain_reg.extend(map(lambda x: '(http|https):\/\/' + x.replace('.', '\.') + '.*|', self.domain_reg_list))
        tmp_domain_reg = ''.join(domain_reg)
        self.domain_reg = tmp_domain_reg[:-1] + '$'

    def run(self, domain_list):
        if not isinstance(domain_list, list):
            raise Exception('domains must be list')
        self.domain_reg_list = self.parse_domain(domain_list) if not self.domain_reg_list else self.domain_reg_list
        self._init_reg()
        self._consist_exclude_urls_regex()
        for domain in domain_list:
            self.crawl_url(domain)
        print('all tasks done')
        print(self.url_dict)

    def crawl_url(self, domain):
        print('enter crawler:{}'.format(domain))
        if 'http' not in domain:
            init_url = 'http://' + domain
        else:
            init_url = domain

        self.current_crawl_queue.append(init_url)
        while self.current_depth < self.depth:
            if len(self.url_dict.keys()) >= self.max_url_nums:
                break
            print('now depth is:{}'.format(self.current_depth))
            for url in self.current_crawl_queue:
                if not url.endswith('.js'):
                    self._crawler_handler(url)
            # 将下一轮待爬取的url提升到当前
            self.current_crawl_queue = self.next_crawl_queue
            self.current_depth += 1

    def filter_url_by_domain(self, url):
        """
        检验当前的url是否满足条件
        是  的url以及不在[不需要]的url集合里,返回True.不满足要求，返回false
        :param url:
        :return:
        """
        # 校验域名
        if not re.match(self.domain_reg, url, flags=0):
            return False
        if len(self.exclude_urls) == 0:
            return True
        # 校验exclude_urls
        if re.match(self.exclude_urls_reg_str, url, flags=0):
            return False
        return True

    def filter_ext(self, url):
        """
        过滤掉特殊后缀的url, 如一些静态资源等等
        如果存在url的后缀是需要排除的，则排除
        :param url:
        :return:
        """
        try:
            f = url.split('/')[-1].strip()
            if '.' in f:
                ext = f.split('.')[-1].strip().lower()
                if ext and ext in self.filter_exts:
                    return True
                else:
                    return False
            return True
        except Exception as e:
            msg = traceback.format_exc()
            print(msg)
            return False

    def _check_crawled_url(self, url):
        """
        检查是否已爬取,不存在,则返回True
        :param url:
        :return:
        """
        if url in self.url_cache:
            return False
        return True

    def _check_url_is_exist_by_md5(self, url_dict):
        """
        利用MD5去检查url是否重复
        :param url_dict:
        :return:
        """
        try:
            exist_md5 = list(url_dict.keys())[0]
            if exist_md5 in self.url_dict:
                return False
            return True
        except Exception as e:
            msg = traceback.format_exc()
            print(msg)
            return True

    def _handle_url(self, req_list):
        """
        处理爬到的url, 看看是不是需要过滤或者是不是已经爬取过了
        :param req_list:
        :return:
        """
        if not req_list:
            return
        insert_req_list = list()
        for req in req_list:
            url = req['originUrl']
            if url.endswith('/'):
                url = url[:-1]
            url_without_protocol = url.split('//')[-1]
            '''
            解析完成后,返回的结构体包括:url,queryString(if exist),method
            需要对url做判断：
            1、是否存在于最后的url集合里
            2、是否已爬过
            3、url的后缀是否在需要过滤的集合里(最先判断,如果需要过滤则直接忽略)
            '''
            md5 = self.calculate_md5(req)
            tmp_dict = {
                md5: req
            }
            if self._check_url_is_exist_by_md5(tmp_dict):
                if len(self.url_dict.keys()) < self.max_url_nums:
                    self.url_dict[md5] = req
                    insert_req_list.append({'taskId': self.task_id, 'urlDict': json.dumps(req)})
                # 如果没有爬过,则放入下一轮要爬取的队列里
                if self._check_crawled_url(url_without_protocol):
                    # 待爬队列已满,则不往队列里添加元素
                    if len(self.next_crawl_queue) < self.max_queue_length:
                        self.next_crawl_queue.append(req['originUrl'])
                        self.url_cache.add(url_without_protocol)

    # 计算MD5
    @staticmethod
    def calculate_md5(url_har):
        url = url_har['url']
        # 有些post请求后缀会加timestamp时间戳来防重放
        tmp_list = url.split('//')[-1].split("?")
        url_without_protocol = tmp_list[0] if len(tmp_list) > 1 else url.split('//')[-1]
        method = url_har['method']
        query_string = ''
        post_data = ''
        if 'queryString' in url_har:
            query_string = url_har['queryString']
        if 'postData' in url_har:
            post_data = url_har['postData']
        tmp_str = url_without_protocol + '&' + method + '&' + query_string + post_data
        return hashlib.md5(tmp_str.encode('utf-8')).hexdigest()

    @staticmethod
    def parse_static_url(url):
        """
        把解析到的静态url, 重新组合成一个字典
        {
            'url': 'xxxxxx',
            'originUrl': 'xxxxxx/a=aa',
            'method': 'GET',
            'queryString': 'a=aa'
        }
        :param url:
        :return:
        """
        try:
            req = dict()
            req['method'] = 'GET'
            req['originUrl'] = url
            if '?' not in url:
                req['url'] = url
                return req
            url_consist = url.split('?')
            req['url'] = url_consist[0]
            params = url_consist[1]
            if '&' not in params:
                params_consist = params.split('=')
                req['queryString'] = params_consist[0] if params_consist[0] else ''
                return req
            multi_params = params.split('&')
            params_list = list(map(lambda y: y.split('=')[0], filter(lambda x: '=' in x, multi_params)))
            # 按首字母把参数排序
            params_list.sort()
            req['queryString'] = ''.join([key + '=&' for key in params_list])[:-2]
            return req
        except Exception as e:
            msg = traceback.format_exc()
            print(msg)
            return None

    @staticmethod
    def _parse_post_data(post_data) -> str:
        """
        解析动态请求获取里面的data成一个字符串
        :param post_data:
        :return:
        """
        if not post_data:
            return ''
        if not isinstance(post_data, dict):
            if '=' in post_data:
                param_dict = {}
                if '&' in post_data:
                    params_couples = post_data.split('&')
                    for param in params_couples:
                        if '=' not in param:
                            continue
                        k, v = param.split('=')
                        param_dict[k] = v
                else:
                    k, v = post_data.split('=')
                    param_dict[k] = v
                post_data = param_dict
            else:
                post_data = json.loads(post_data)
        post_data_list = [k for k, __ in post_data.items()]
        post_data_list.sort()
        return ''.join([param + '&' for param in post_data_list])[:-1]

    def _consist_exclude_urls_regex(self):
        self.exclude_urls_reg_str = '|'.join(self.exclude_urls) if len(self.exclude_urls) else ''
        print('exclude url reg is'.format(self.exclude_urls_reg_str))

    def static_crawler(self, page, results, url) -> List["ElementHandle"]:
        """
        主要用于页面中静态url的解析, 目前涵盖了a标签的href属性和src属性
        """
        links = page.query_selector_all("//a")
        tmp_link = []
        for link in links:
            href = link.get_property("href").json_value()
            src = link.get_property("src").json_value()
            if not href or href == url:
                continue
            if self.filter_ext(url=href) and self.filter_url_by_domain(url=href):
                req = self.parse_static_url(href)
                if req:
                    print('href:{}'.format(req))
                    results.append(req)
            if not src or src == url:
                continue
            if self.filter_ext(url=src) and self.filter_url_by_domain(url=src):
                req = self.parse_static_url(src)
                if req:
                    print('src:{}'.format(req))
                    results.append(req)
            if 'javascript' in href or 'javascript' in src:
                tmp_link.append(link)
        return tmp_link

    def _crawler_handler(self, url):
        print('start crawling url:{}'.format(url))
        results = []

        def log_and_continue_request(route: Route, request: Request):
            resource_type = request.resource_type
            '''请求过滤'''
            if resource_type in ['image', 'media', 'eventsource', 'websocket']:
                route.abort()
            else:
                url_origin = request.url
                headers = request.headers
                method = request.method
                post_data_json = request.post_data_json
                print(url_origin, headers, method, post_data_json)
                if not url_origin:
                    route.continue_()
                    return
                if not self.filter_url_by_domain(url_origin) or self.filter_ext(url_origin):
                    route.continue_()
                    return
                http_har = dict()
                if method == 'POST' or method == 'PUT':
                    post_data_origin = post_data_json
                    post_data_handled = self._parse_post_data(post_data_origin)
                    content_type = headers['content-type'] if 'content-type' in headers else ''
                    http_har['originPostData'] = post_data_origin
                    http_har['postData'] = post_data_handled
                    http_har['contentType'] = content_type
                    http_har['url'] = url_origin
                    http_har['originUrl'] = url_origin
                    http_har['method'] = method
                if method == 'GET':
                    http_har = self.parse_static_url(url_origin)
                results.append(http_har)
                route.continue_()

        with sync_playwright() as p:
            browser = p.webkit.launch(headless=True, chromium_sandbox=True, )
            page = browser.new_page()
            page.set_default_navigation_timeout(30000)
            if self.cookie:
                self.header['Cookie'] = self.cookie
            page.set_extra_http_headers(headers=self.header)
            page.route('**/*', log_and_continue_request)
            page.goto(url)
            page.wait_for_load_state(state="networkidle", timeout=30000)

            tmp_link = self.static_crawler(page, results, url)
            for link in tmp_link:
                link.click()
                self.static_crawler(page, results, url)

            browser.close()

        self._handle_url(results)


if __name__ == '__main__':
    start_time = time.time()
    crawler = Crawler(5, 5000, "", )
    end_time = time.time()
    print('all spent time is: {}'.format(end_time - start_time))
