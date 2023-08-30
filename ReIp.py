 #coding=utf-8
import argparse
import os
import re
import signal
import time
import requests
from fake_useragent import UserAgent
from termcolor import colored
from tqdm import tqdm
import urllib.parse
import urllib.request
from urllib.error import HTTPError
import concurrent.futures
import whois
import json
from lxml import etree

requests.packages.urllib3.disable_warnings()

queried_domains = set()  # whois查询后存入其中
ua = UserAgent()


def usage():
    print(colored('''

    +-----------------------------------------------------------------+

         ____                                ___ ____  
        |  _ \ _____   _____ _ __ ___  ___  |_ _|  _ \ 
        | |_) / _ \ \ / / _ \ '__/ __|/ _ \  | || |_) |
        |  _ <  __/\ V /  __/ |  \__ \  __/  | ||  __/ 
        |_| \_\___| \_/ \___|_|  |___/\___| |___|_|      

        用法:
              python ReveseIP.py -u x.x.x.x
              python ReveseIP.py -f 1.txt 
        参数:
              -u  指定查询IP
              -f  指定文件批量查询
              -t  指定线程数 默认线程数6


    +-----------------------------------------------------------------+                                         

    ''', 'cyan'))


def signal_handler(sig, frame):
    exit(0)


def ip138_Inquire(url):
    ip138_headers = {
        "Host": "site.ip138.com",
        # "Cookie": "Hm_lvt_d9ca33e29b072e45bd3276e2d4785341=1687416576; Hm_lpvt_d9ca33e29b072e45bd3276e2d4785341=1687416576",
        "User-Agent": ua.random,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Te": "trailers",
        "Connection": "close"

    }

    ip138_url = 'https://site.ip138.com/' + str(url) + '/'
    try:
        ip138_res = requests.get(url=ip138_url, headers=ip138_headers, timeout=3.5).text
        if '<li>暂无结果</li>' not in ip138_res:
            result_site = re.findall(r"""</span><a href="/(.*?)/" target="_blank">""", ip138_res)
            return result_site
    except Exception as e:
        print(colored("138error", "red"))
        pass


def izhan(url):
    azheaders = {

        'Host': 'dns.aizhan.com',

        'User-Agent': ua.random,

        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',

        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',

        'Accept-Encoding': 'gzip, deflate, br',

        'Referer': 'https://dns.aizhan.com/'}

    aizhan_url = 'https://dns.aizhan.com/' + str(url) + '/'
    try:
        aizhan_r = requests.get(url=aizhan_url, headers=azheaders, timeout=3).text
        aizhan_nums = re.findall(r'''<span class="red">(.*?)</span>''', aizhan_r)
        if int(aizhan_nums[0]) > 0:
            aizhan_domains = re.findall(r'''rel="nofollow" target="_blank">(.*?)</a>''', aizhan_r)
            return aizhan_domains
    except Exception as e:
        print(colored("izhanerror", "red"))
        pass


# 百度权重
def getPc(domain):
    ua_header = UserAgent()
    headers = {
        'Host': 'baidurank.aizhan.com',
        'User-Agent': ua_header.random,
        'Sec-Fetch-Dest': 'document',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Cookie': ''
    }
    aizhan_pc = 'https://baidurank.aizhan.com/api/br?domain={}&style=text'.format(domain)
    try:
        req = urllib.request.Request(aizhan_pc, headers=headers)
        response = urllib.request.urlopen(req, timeout=2)
        b = response.read()
        a = b.decode("utf8")
        result_pc = re.findall(re.compile(r'>(.*?)</a>'), a)
        pc = result_pc[0]

    except HTTPError as u:
        time.sleep(3)
        return getPc(domain)
    return pc


# 移动权重
def getMobile(domain):
    ua_header = UserAgent()
    headers = {
        'Host': 'baidurank.aizhan.com',
        'User-Agent': ua_header.random,
        'Sec-Fetch-Dest': 'document',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Cookie': ''
    }
    aizhan_pc = 'https://baidurank.aizhan.com/api/mbr?domain={}&style=text'.format(domain)
    try:
        req = urllib.request.Request(aizhan_pc, headers=headers)
        response = urllib.request.urlopen(req, timeout=2)
        b = response.read()
        a = b.decode("utf8")
        result_m = re.findall(re.compile(r'>(.*?)</a>'), a)
        mobile = result_m[0]
    except HTTPError as u:
        time.sleep(2)
        return getMobile(domain)
    return mobile


def status(url):
    try:
        # signal.signal(signal.SIGINT, signal_handler)
        try:
            #  signal.signal(signal.SIGINT, signal_handler)
            status_cd = requests.get(url="https://" + url, timeout=2)
            status_cd.encoding = status_cd.apparent_encoding
            title = re.findall(r"<title.*?>(.+?)</title>", status_cd.text)
            http_code = status_cd.status_code
            http_mobile = getMobile(url)
            http_pc = getPc(url)
            print(colored("url:" + "https://" + url, "cyan") + colored("'status':" + str(http_code), 'green') + colored(
                "  Title:" + ''.join(title), 'magenta') + colored("  百度权重：" + http_pc + "  移动权重：" + http_mobile,
                                                                  "blue"))
            return ("url:" + "https://" + url + "'status':" + str(http_code) + "  Title:" + ''.join(
                title) + "  百度权重：" + http_pc + "  移动权重：" + http_mobile)
        except Exception as e:
            #  signal.signal(signal.SIGINT, signal_handler)
            status_cd = requests.get(url="http://" + url, timeout=2)
            status_cd.encoding = status_cd.apparent_encoding
            title = re.findall(r"<title.*?>(.+?)</title>", status_cd.text)
            https_code = status_cd.status_code
            https_mobile = getMobile(url)
            https_pc = getPc(url)
            print(colored("url:" + "http://" + url, "cyan") + colored("'status':" + str(https_code), 'green') + colored(
                "  Title:" + ''.join(title), 'magenta') + colored(
                "  百度权重：" + https_pc + "  移动权重：" + https_mobile, "blue"))
            return ("url:" + "http://" + url + "'status':" + str(https_code) + "  Title:" + ''.join(
                title) + "  百度权重：" + https_pc + "  移动权重：" + https_mobile)
    except Exception as e:
        pass


# whois查询去重
data = []


def whois_domain(domain):
    dot_count = domain.count(".")
    if dot_count >= 2:
        pattern = r"\.(.*)"
        match = re.search(pattern, domain)
        match_add = match.group(1)
        data.append(match_add)
    else:
        data.append(domain)


# icp备案查询接口
def icp_domain(domain):
    try:
        head = {
            'Host': 'icp.aizhan.com',
            'User-Agent': ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate, br',
            'Referer': 'https://icp.aizhan.com/',
            'X-Forwarded-For': '127.0.0.1',
            'Sec-Ch-Ua-Mobile': '?0',
            'Te': 'trailers',
            'Connection': 'close'
        }

        icp_url = f'https://icp.aizhan.com/{domain}/'
        req = requests.get(url=icp_url, headers=head, timeout=2)
        # b = req.content.decode('gbk')
        content = req.content
        output = content.decode('utf-8', 'ignore')
        # 创建解析器
        parser = etree.HTMLParser()
        # 解析HTML
        tree = etree.fromstring(output, parser)
        # 使用xpath进行匹配
        # company_name = tree.xpath = ('//tr[1]/')
        company_name = tree.xpath('//tr[1]/td[2]/text()')[0].strip()
        company_property = tree.xpath('//tr[2]/td[2]/text()')[0].strip()
        icp_number = tree.xpath('//tr[3]/td[2]/span/text()')[0].strip()
        website_name = tree.xpath('//tr[4]/td[2]/text()')[0].strip()
        homepage_url = tree.xpath('//tr[5]/td[2]/text()')[0].strip()
        print(
            colored(
                f'[+]icp查询结果 主办单位名称:{company_name} 主办单位性质:{company_property} 网站备案/许可证号:{icp_number} 网站名称:{website_name} 网站首页网址:{homepage_url} ',
                'cyan'))
    except:
        pass


def http_request(urls, Thread, flag):
    req_ret = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=Thread)
    for url in urls:
        ret = executor.submit(status, url)
        req_ret.append(ret)
    if flag == 1:
        concurrent.futures.wait(req_ret)
    if flag == 2:
        with open('output.txt', 'w') as p:
            p.write("")
        for ret in concurrent.futures.as_completed(req_ret):
            signal.signal(signal.SIGINT, signal_handler)
            result = ret.result()
            if result != None:
                with open('output.txt', 'a') as p:
                    p.write(result + "\n")


def check_U(url, Thread):
    try:
        ret_138 = ip138_Inquire(url)
        ret_izhan = izhan(url)
        ret_and = ret_138 + ret_izhan
        ret_and = list(set(ret_and))
        print(colored(f'==========IP反查域名及域名权重==========--{len(ret_and)}个目标结果', 'white'))
        t1 = time.time()
        http_request(ret_and, Thread, 1)
        t2 = time.time()
        for i in ret_and:
            whois_domain(i)
        whois_icp(data)
        data.clear()
        print(colored("\n用时:" + str(t2 - t1) + "s", 'yellow'))

    except:
        print(colored("网络错误，请重新尝试", 'red'))


def check_F(filepath, Thread):
    try:
        with open(filepath, 'r') as f:
            urls = f.readlines()
        t1 = time.time()
        for url in urls:
            # signal.signal(signal.SIGINT, signal_handler)
            print(colored("当前ip:" + url, 'red'))
            try:
                ret_138 = ip138_Inquire(url)
                ret_izhan = izhan(url)
                ret_and = ret_138 + ret_izhan
                ret_and = list(set(ret_and))
                print(colored(f'==========IP反查域名及域名权重=--{len(ret_and)}个目标结果=========', 'white'))
                # for i in ret_and:
                #     whois_domain(i)
                # whois_icp(data)
                # data.clear()
            except:
                print(colored("网络错误，请重新尝试", 'red'))
            http_request(ret_and, Thread, 2)
            for i in ret_and:
                whois_domain(i)
            whois_icp(data)
            data.clear()
        t2 = time.time()
        for i in ret_and:
            whois_domain(i)
        data.clear()
        print(colored("\n用时:" + str(t2 - t1) + "s", 'yellow'))
    except:
        pass


# whois/icp查询函数
def whois_icp(data):
    try:
        if data:
            data1 = list(set(data))
            print(colored(f'==========whois和icp备案查询{len(data1)}个域名结果==========', "white"))
            if len(data1) >= 1:
                for i in data1:
                    w = whois.whois(i)
                    if w["domain_name"] is None:
                        print(colored(f'[-]{str(i)}域名内容为空或该域名没有注册或数据加载失败', 'red'))
                    else:
                        #           print(colored(
                        #                         f"[+]whois查询结果 域名:{str(w.domain_name)} 注册商:{str(w.registrar)} 联系人:{str(w.name)} 邮箱地址:{str(w.emails)} 创建时间:{str(w.creation_date)} 状态:{str(w.status)}",'orange'))
                        domian_name = (str(w.domain_name))
                        registrar = (str(w.registrar))
                        name = (str(w.name))
                        emails = (str(w.emails))
                        creation_date = (str(w.creation_date))
                        status = (str(w.status))
                        print(
                            f'[+]whois查询结果 域名{domian_name} 注册商:{registrar} 联系人:{name} 邮箱地址:{emails} 创建时间:{creation_date} 状态:{status}',
                            "orange")
                    time.sleep(0.5)
                for i in data1:
                    icp_domain(i)

            data.clear()


    except:
        print('报错')


def main():
    parse = argparse.ArgumentParser()
    parse.add_argument("-u", "--url", help="python pegging.py -u url")
    parse.add_argument("-f", "--file", help="python pegging.py -f file")
    parse.add_argument("-t", "--Thread", help="python pegging.py -t Thread")
    args = parse.parse_args()
    Thread = args.Thread
    url = args.url
    #url = '202.196.208.7'
    filepath = args.file
    # filepath ='D:\\百度网盘\\python\\工具开发\\ip反查\\2.0\\3.0\\1.txt'
    if url == None and filepath == None:
        # usage()
        return
    if Thread == None:
        Thread = 5
    else:
        Thread = int(Thread)
    if url != None:
        check_U(url, Thread)
    if filepath != None:
        check_F(filepath, Thread)


if __name__ == '__main__':
    os.system('chcp 65001')
    usage()
    main()
