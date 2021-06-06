import hashlib
import json
import os
import re
import time
import traceback

from multiprocessing import Manager, Pool
from typing import List

from bloompy import BloomFilter
from playwright.sync_api import sync_playwright, Request, ElementHandle, Route, Browser

DEFAULT_HEADERS = {
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/90.0.4430.212 Safari/537.36'
}

FORM_FILL_UPLOAD_JS = '''
function form_upload(){
                    console.log('form_upload start')
                    var formList = document.getElementsByTagName("form");
                    var resultList = []
                    var reset_name = ["重置","清空", "reset", "clear", "附件", "选择文件", "选择附件", "上传", "选择", "请选择附件", "刷新"]
                    for (var i=0;i<formList.length;i++) {
                        for (var j=0;j<formList[i].length;j++){
                            if (formList[i][j].type === "text" || formList[i][j].type === "password") {
                                formList[i][j].value = "11111111"
                            }
                            if (formList[i][j].tagName.toLowerCase() === "select" || formList[i][j].type === "hidden") {
                                formList[i][j].value = "1"
                            }
                        }
                        for(var j=0;j<formList[i].length;j++) {
                                if (formList[i][j].tagName.toLowerCase() === "button" && !reset_name.includes(formList[i][j].innerText.toLowerCase().trim())) {
                                     console.log(formList[i][j])
                                     formList[i][j].click()
                                }
                                if (formList[i][j].type.toLowerCase() === "submit") {
                                    formList[i][j].click()
                                }
                        }  
                    }
                }
'''


class Crawler(object):
    def __init__(self, cookie: str = None, headers: dict = None, max_num: int = 10000, domain_regs: list = None,
                 depth: int = 5):
        self.cookie = cookie
        self.headers = headers if headers else DEFAULT_HEADERS
        self.waiting_queue = Manager().Queue(maxsize=max_num * 2)
        self.current_queue = Manager().Queue(maxsize=max_num * 2)
        self.max_url_num = max_num
        self.crawled_urls = BloomFilter(element_num=max_num * 5, error_rate=0.01)
        self.url_dict = Manager().dict()
        self.domain_reg_list = domain_regs
        self.depth = depth
        self.current_depth = 0
        self.filter_exts = [
            'css', 'png', 'gif', 'jpg', 'jpeg', 'swf', 'tiff',
            'pdf', 'ico', 'flv', 'mp4', 'mp3', 'avi', 'mpg', 'gz',
            'mpeg', 'iso', 'dat', 'mov', 'rar', 'exe', 'zip', 'tar',
            'bin', 'bz2', 'xsl', 'doc', 'docx', 'ppt', 'pptx', 'xls',
            'xlsx', 'csv', 'map', "ttf", 'tif', 'woff', 'woff2',
            'cab', 'apk', 'bmp', 'svg', 'exif', 'xml', 'rss', 'webp', 'js'
        ]

    def run(self, urls):
        self.consist_headers()
        # 默认只爬取当前根域下的url
        self.domain_reg_list = self.parse_domain(urls) if not self.domain_reg_list else self.domain_reg_list
        self._init_reg()
        for url in urls:
            self.call_crawl_handler(url)
        print('all task done')
        print(self.url_dict)

    def call_crawl_handler(self, url):
        if 'http' not in url:
            init_url = 'http://' + url
        else:
            init_url = url
        self.current_queue.put_nowait(init_url)
        # 初始化url为了避免重复爬取，在初始化时就放入布隆过滤器
        init_url_without_protocol = url.split('//')[-1]
        self.crawled_urls.add(init_url_without_protocol)
        while self.current_depth < self.depth:
            if len(self.url_dict) >= self.max_url_num:
                print('达到预设爬去上限, 爬虫结束')
                break
            print('now crawl depth is :{}'.format(self.current_depth))
            tmp_results = []
            # 利用进程池去完成爬虫
            pool = Pool(os.cpu_count() * 2)
            while not self.current_queue.empty():
                print('当前在待爬队列中还有:{}个url'.format(self.current_queue.qsize()))
                url = self.current_queue.get_nowait()
                if not url.endswith('js'):
                    result = pool.apply_async(func=self.crawl_handler, args=(url,))
                    tmp_results.append(result)
                    # self.crawl_handler(url)
            pool.close()
            pool.join()
            tmp_reqs = []
            for result in tmp_results:
                for r in result.get():
                    tmp_reqs.append(r)
            self._handle_url(tmp_reqs)
            self.current_queue = self.waiting_queue
            self.waiting_queue = Manager().Queue(maxsize=self.max_url_num * 2)
            self.current_depth += 1
            print('depth:{} crawled done'.format(self.current_depth))

    def consist_headers(self):
        if self.cookie:
            self.headers['Cookie'] = self.cookie

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
            if '.io' in domain:
                return domain.split('.xyz')[0] + '.io'
            # 针对ip:port形式的url,截取/即可
            return domain.split('/')[0]

        return [_split_url_protocol_and_path(domain) for domain in domain_list]

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
        post_data_list = [k for k, _ in post_data.items()]
        post_data_list.sort()
        return ''.join([param + '&' for param in post_data_list])[:-1]

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
        except Exception:
            msg = traceback.format_exc()
            print(msg)
            return None

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
            return False
        except Exception:
            msg = traceback.format_exc()
            print(msg)
            return False

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
        # TODO: 后续补齐这部分功能
        # if len(self.exclude_urls) == 0:
        #    return True
        # 校验exclude_urls
        # if re.match(self.exclude_urls_reg_str, url, flags=0):
        #    return False
        return True

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
            if not self.filter_ext(url=href) and self.filter_url_by_domain(url=href):
                req = self.parse_static_url(href)
                if req:
                    print('href:{}'.format(req))
                    results.append(req)

            if not src or src == url:
                continue
            if not self.filter_ext(url=src) and self.filter_url_by_domain(url=src):
                req = self.parse_static_url(src)
                if req:
                    print('src:{}'.format(req))
                    results.append(req)

            # 这里主要是用于有些a标签里的写法是<javascript>标签，用于执行某些js操作
            if 'javascript' in href or 'javascript' in src:
                tmp_link.append(link)
        return tmp_link

    def _check_crawled_url(self, url) -> bool:
        """
        检查是否已爬取,不存在,则返回True
        :param url:
        :return:
        """
        if url in self.crawled_urls:
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
            if exist_md5 in self.crawled_urls:
                return False
            return True
        except Exception:
            msg = traceback.format_exc()
            print(msg)
            return True

    @staticmethod
    def calculate_md5(url_har):
        """
        计算md5来去重
        :param url_har:
        :return:
        """
        url = url_har['url']
        # 有些post请求后缀会加timestamp时间戳来防重放
        tmp_list = url.split('//')[-1].split('?')
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
                if len(self.url_dict.keys()) < self.max_url_num:
                    self.url_dict[md5] = req
                    # TODO:后面可以定制化插入taskId
                    insert_req_list.append({'taskId': 'test12', 'urlDict': json.dumps(req)})
                # 如果没有爬过,则放入下一轮要爬取的队列里
                if self._check_crawled_url(url_without_protocol) and not self.waiting_queue.full():
                    self.waiting_queue.put_nowait(req['originUrl'])
                    self.crawled_urls.add(url_without_protocol)

    def crawl_handler(self, url) -> list:
        result = []

        def intercept(route: Route, request: Request):
            # 拦截前端跳转,主要方法是修改请求响应为204 TODO: 后续在遇到前端跳转的时候，优化hook逻辑
            if request.is_navigation_request() and request.frame.parent_frame:
                request.response().status = 204
                route.continue_()
                return
            # 尝试拦截后端跳转
            if request.redirected_to:
                if request.post_data_json:
                    request.response().status = 200
                    self.waiting_queue.put_nowait(request.redirected_to.url)
                else:
                    ...
                route.continue_()
                return
            resource_type = request.resource_type
            # 过滤动态请求
            if resource_type in ['image', 'media', 'eventsource', 'websocket']:
                route.abort()
            else:
                url_origin = request.url
                if not url_origin:
                    route.continue_()
                    return
                if not self.filter_ext(url=url_origin) and self.filter_url_by_domain(url=url_origin):
                    headers = request.headers
                    method = request.method
                    post_data_json: dict = request.post_data_json
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
                    result.append(http_har)
                route.continue_()

        with sync_playwright() as p:
            browser = p.webkit.launch(headless=True, chromium_sandbox=True, )
            page = browser.new_page()
            page.set_default_navigation_timeout(30000)
            page.set_extra_http_headers(self.headers)
            page.route('**/*', intercept)
            page.goto(url)
            page.wait_for_load_state(state='networkidle', timeout=30000)

            tmp_links = self.static_crawler(page, result, url)
            page.evaluate(FORM_FILL_UPLOAD_JS)
            for link in tmp_links:
                link.click()
            page.close()
            browser.close()
        return result


if __name__ == '__main__':
    start_time = time.time()
    crawler = Crawler()
    crawler.run(['https://www.baidu.com/sss'])
    end_time = time.time()
    print('spent time:{}'.format(end_time - start_time))
