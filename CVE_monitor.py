#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author : anonymous
# @Time   : 2025-12-15
# @File   : CVE_monitor.py
# -----------------------------------------------
# 融合OSCS1024漏洞库、安天、Tenable微软安全中心、CVE平台的漏洞信息爬取及推送脚本
# -----------------------------------------------

import json
import requests
from datetime import datetime, timedelta
import hashlib
import os
import logging
import traceback
from logging.handlers import TimedRotatingFileHandler
from abc import ABCMeta, abstractmethod
from lxml import etree  # 导入lxml.etree模块
import re  # 导入re模块
import sqlite3
import time
import yaml
import telegram

# 确保目录存在
PRJ_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(PRJ_DIR, 'log')
CACHE_DIR = os.path.join(PRJ_DIR, 'cache')
ARCHIVE_DIR = os.path.join(PRJ_DIR, 'archive')
STATIC_DIR = os.path.join(PRJ_DIR, 'static')
RSS_DIR = os.path.join(PRJ_DIR, 'RSS')

# 创建目录
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(ARCHIVE_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(RSS_DIR, exist_ok=True)

# 日志配置
RUN_LOG = os.path.join(LOG_DIR, 'run.log')
ERR_LOG = os.path.join(LOG_DIR, 'err.log')

def init_log(runlog=RUN_LOG, errlog=ERR_LOG):
    """
    初始化日志配置 （只需在程序入口调用一次）
    :return: None
    """
    # 全局配置
    logger = logging.getLogger()
    logger.setLevel("DEBUG")
    BASIC_FORMAT = "%(asctime)s [%(levelname)s] : %(message)s"
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(BASIC_FORMAT, DATE_FORMAT)

    # 输出到控制台的 handler，设置UTF-8编码
    ch = logging.StreamHandler()
    # 设置控制台输出编码为UTF-8
    import sys
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    ch.setFormatter(formatter)
    ch.setLevel("DEBUG")
    logger.addHandler(ch)

    # 输出到运行日志文件的 handler
    fh = TimedRotatingFileHandler(filename=runlog, when="MIDNIGHT", interval=1, backupCount=7, encoding='utf-8')
    fh.setFormatter(formatter)
    fh.setLevel("INFO")
    logger.addHandler(fh)

    # 输出到异常日志文件的 handler
    exfh = TimedRotatingFileHandler(filename=errlog, when="MIDNIGHT", interval=1, backupCount=7, encoding='utf-8')
    exfh.setLevel("ERROR")
    exfh.setFormatter(formatter)
    logger.addHandler(exfh)

    # 禁用第三方日志
    logging.getLogger("requests").setLevel(logging.FATAL)

init_log()

def log_debug(msg):
    """
    打印调试信息
    :param msg: 日志信息
    :return: None
    """
    logging.debug(msg)

def log_info(msg):
    """
    打印正常信息
    :param msg: 日志信息
    :return: None
    """
    logging.info(msg)

def log_warn(msg):
    """
    打印警告信息
    :param msg: 日志信息
    :return: None
    """
    logging.warning(msg)

def log_error(msg):
    """
    打印异常信息和异常堆栈
    :param msg: 日志信息
    :return: None
    """
    logging.exception(msg)
    logging.exception(traceback.format_exc())

class VulnerabilityInfo:
    """
    漏洞信息类
    """

    def __init__(self):
        self.id = ''  # 漏洞唯一标识符
        self.title = ''
        self.time = ''
        self.ids = []
        self.source = ''
        self.detail_url = ''
        self.md5 = ''
        self.cve = ''  # 添加cve属性
        self.src = ''   # 添加src属性

    def is_valid(self):
        return bool(self.title)

    def MD5(self):
        if not self.md5:
            data = '%s%s%s' % (self.title, self.time, self.detail_url)
            self.md5 = hashlib.md5(data.encode(encoding='UTF-8')).hexdigest()
        return self.md5

    def to_msg(self):
        return '\n'.join([
            "\n==============================================",
            "[ 标题 ] %s" % self.title,
            "[ 时间 ] %s" % self.time,
            "[ 编号 ] %s" % ', '.join(self.ids),
            "[ 来源 ] %s" % self.source,
            "[ 详情 ] %s" % self.detail_url
        ])

class CVEInfo(VulnerabilityInfo):
    """
    漏洞信息类
    """

    def __init__(self):
        super().__init__()
        self.info = ''

    def to_msg(self):
        return '\n'.join([
            "\n==============================================",
            "[ 标题  ] %s" % self.title,
            "[ 时间  ] %s" % self.time,
            "[ 编号  ] %s" % self.cve,
            "[ 来源  ] %s" % self.source,
            "[ 详情  ] %s" % self.detail_url
        ])

class BaseCrawler:
    """
    爬虫基类
    """
    __metaclass__ = ABCMeta  # 定义为抽象类

    def __init__(self, timeout=60, charset='utf-8'):
        self.timeout = timeout or 60
        self.charset = charset or 'utf-8'

    @abstractmethod
    def NAME_CH(self):
        return '未知'

    @abstractmethod
    def NAME_EN(self):
        return 'unknown'

    def headers(self):
        return {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
        }

    def vulnerabilities(self):
        log_info('++++++++++++++++++++++++++++++++++++++++++++')
        log_info('正在获取 [%s] 漏洞信息...' % self.NAME_CH())

        try:
            # 获取新的漏洞信息
            new_vulnerabilities = self.get_vulnerabilities()
            
            # 每次获取当前日期，确保日期变化时能获取新的漏洞
            target_date = datetime.now().strftime('%Y-%m-%d')
            log_info(f'使用目标日期: {target_date} 过滤漏洞信息')
            
            # 过滤指定日期的漏洞
            filtered_vulnerabilities = self.filter_by_date(new_vulnerabilities, target_date)
        except Exception as e:
            filtered_vulnerabilities = []
            log_error('获取 [%s] 漏洞信息异常: %s' % (self.NAME_CH(), str(e)))

        log_info('得到 [%s] 最新漏洞信息 [%s] 条' % (self.NAME_CH(), len(filtered_vulnerabilities)))
        log_info('--------------------------------------------')
        return filtered_vulnerabilities

    def cves(self):
        log_info('++++++++++++++++++++++++++++++++++++++++++++')
        log_info('正在获取 [%s] 威胁情报...' % self.NAME_CH())

        try:
            # 获取新的威胁情报
            new_cves = self.get_cves()
            
            # 过滤已经存在于数据库中的威胁情报
            filtered_cves = []
            for cve in new_cves:
                if hasattr(cve, 'id') and cve.id and not is_vulnerability_exists(cve.id):
                    filtered_cves.append(cve)
                    log_info(f"发现新威胁情报：{cve.title}，ID：{cve.id}")
                else:
                    if hasattr(cve, 'title'):
                        log_info(f"威胁情报已存在于数据库中，跳过：{cve.title}")
            
            log_info(f'得到 [{self.NAME_CH()}] 新增威胁情报 [{len(filtered_cves)}/{len(new_cves)}] 条')
        except Exception as e:
            filtered_cves = []
            log_error('获取 [%s] 威胁情报异常: %s' % (self.NAME_CH(), str(e)))

        log_info('--------------------------------------------')
        return filtered_cves

    @abstractmethod
    def get_vulnerabilities(self):
        return []

    @abstractmethod
    def get_cves(self):
        try:
            # 获取 RSS 数据
            response = requests.get(self.rss_url)
            data = response.content
            
            # 解析 RSS 数据
            rss = etree.XML(data)
            
            # 提取漏洞信息
            cves = []
            for item in rss.xpath('//item'):
                title = item.xpath('./title/text()')[0]
                link = item.xpath('./link/text()')[0]
                pub_date = item.xpath('./pubDate/text()')[0]
                
                # 格式化时间
                # time_struct = time.strptime(pub_date, '%a, %d %b %Y %H:%M:%S %Z')
                # formatted_time = time.strftime('%Y-%m-%d %H:%M:%S', time_struct)
                
                # 提取 CVE ID
                cve_id = title.split(' ')[0]
                
                cves.append({
                    'title': title,
                    'time': pub_date,
                    'id': cve_id,
                    'src': 'Tenable',
                    'url': link
                })
            
            return cves
        except Exception as e:
            print(f"获取 Tenable 威胁情报异常: {str(e)}")
            traceback.print_exc()
            return []

    def filter_by_date(self, vulnerabilities, target_date):
        """
        过滤出指定日期的漏洞，并确保不重复推送已经处理过的漏洞
        :param vulnerabilities: 漏洞列表
        :param target_date: 目标日期
        :return: 过滤后的漏洞列表
        """
        filtered = []
        skipped_date = 0
        skipped_exists = 0
        
        for vuln in vulnerabilities:
            # 记录ID和标题用于调试
            vuln_id = getattr(vuln, 'id', '无ID')
            vuln_title = getattr(vuln, 'title', '无标题')
            
            # 首先检查日期是否匹配
            if vuln.time == target_date:
                # 确保ID有效
                if not vuln_id or vuln_id.strip() == '':
                    log_warn(f"漏洞ID无效，跳过: {vuln_title}")
                    skipped_exists += 1
                    continue
                    
                # 检查数据库中是否已经存在此漏洞
                if not is_vulnerability_exists(vuln_id):
                    filtered.append(vuln)
                    log_info(f"发现新漏洞：{vuln_title}，ID：{vuln_id}")
                else:
                    log_info(f"漏洞已存在于数据库中，跳过：{vuln_title}，ID：{vuln_id}")
                    skipped_exists += 1
            else:
                log_info(f"漏洞日期 {vuln.time} 不匹配目标日期 {target_date}，跳过：{vuln_title}")
                skipped_date += 1
                
        # 记录过滤结果
        if skipped_date > 0 or skipped_exists > 0:
            log_info(f"日期筛选: 跳过 {skipped_date} 条非当天漏洞，跳过 {skipped_exists} 条已存在漏洞，保留 {len(filtered)} 条新漏洞")
            
        return filtered

class OSCS1024Crawler(BaseCrawler):
    """
    OSCS1024漏洞库爬虫
    """

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = 'OSCS1024漏洞库'
        self.name_en = 'OSCS1024 Vulnerability Database'
        self.url = 'https://www.oscs1024.com/oscs/v1/vdb/vuln_info'

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def get_vulnerabilities(self):
        response = requests.get(
            self.url,
            headers=self.headers(),
            timeout=self.timeout
        )

        vulnerabilities = []
        if response.status_code == 200:
            data = response.json()
            for item in data:
                vulnerability = self.to_vulnerability(item)
                if vulnerability.is_valid():
                    vulnerabilities.append(vulnerability)
        else:
            log_warn('获取 [%s] 漏洞信息失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
        return vulnerabilities

    def to_vulnerability(self, item):
        vulnerability = VulnerabilityInfo()
        vulnerability.id = item.get('id', '')
        
        # 如果id为空，生成一个唯一ID
        if not vulnerability.id:
            # 使用标题和时间生成MD5作为ID
            title = item.get('title', '')
            time_str = item.get('published_time', '')
            
            # 提取编号作为备选ID
            cnvd_id = item.get('cnvd_id', '')
            cve_id = item.get('cve_id', '')
            mps_id = item.get('mps_id', '')
            
            # 优先使用CVE编号作为ID
            if cve_id:
                vulnerability.id = cve_id
                log_info(f"使用CVE编号作为ID: {cve_id}")
            elif cnvd_id:
                vulnerability.id = cnvd_id
                log_info(f"使用CNVD编号作为ID: {cnvd_id}")
            elif mps_id:
                vulnerability.id = mps_id
                log_info(f"使用MPS编号作为ID: {mps_id}")
            elif title:
                # 如果没有任何编号，则使用标题和时间生成稳定的哈希作为ID
                # 移除时间戳，因为时间戳会导致每次生成不同的ID
                unique_str = f"{title}-{time_str}"
                vulnerability.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
                log_info(f"生成固定哈希ID: {vulnerability.id} (基于标题和发布时间)")
            else:
                # 最后的备选方案，使用固定前缀和当前日期
                current_date = datetime.now().strftime('%Y-%m-%d')
                unique_str = f"oscs1024-unknown-{current_date}"
                vulnerability.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
                log_info(f"生成默认ID: {vulnerability.id} (基于当前日期)")
                
        vulnerability.title = item.get('title', '')
        vulnerability.time = item.get('published_time', '')
        
        # 提取编号
        cnvd_id = item.get('cnvd_id', '')
        cve_id = item.get('cve_id', '')
        mps_id = item.get('mps_id', '')
        
        # 按优先级组合编号
        ids = []
        if cnvd_id:
            ids.append(cnvd_id)
        if cve_id:
            ids.append(cve_id)
        if mps_id:
            ids.append(mps_id)
        vulnerability.ids = ids
        
        # 设置cve属性
        vulnerability.cve = cve_id if cve_id else ''
        vulnerability.src = self.name_ch  # 设置来源
        
        vulnerability.source = 'OSCS1024漏洞库'
        
        # 提取详情链接
        reference_urls = item.get('reference_url_list', [])
        if reference_urls:
            vulnerability.detail_url = reference_urls[0].get('url', '')
        else:
            vulnerability.detail_url = ''
        
        # 记录日志，帮助调试ID重复问题
        log_info(f"处理OSCS1024漏洞: {vulnerability.title}, ID: {vulnerability.id}")
        
        return vulnerability

class AntiYCloud(BaseCrawler):
    """
    安天爬虫
    """

    def __init__(self):
        BaseCrawler.__init__(self)
        self.name_ch = '安天(antiycloud)'
        self.name_en = 'antiycloud'
        self.home_page = 'https://www.antiycloud.com/'
        self.url = 'https://www.antiycloud.com/api/safeNoticeDetail/{}'

    def NAME_CH(self):
        return self.name_ch

    def NAME_EN(self):
        return self.name_en

    def get_cves(self):
        try:
            # 获取当前日期，格式为YYYYMMDD，确保每次使用最新日期
            current_date = datetime.now().strftime("%Y%m%d")
            log_info(f"[{self.NAME_CH()}] 使用当前日期 {current_date} 获取安天威胁情报")
            
            # 构造API URL
            api_url = self.url.format(current_date)
            
            # 发送GET请求
            response = requests.get(api_url, headers=self.headers(), timeout=self.timeout)
            
            if response.status_code == 200:
                # 解析JSON数据
                data = response.json()
                
                # 检查status是否为success
                if data.get("status") == "success":
                    # 提取威胁情报数据
                    intel_data = data.get("data", {})
                    
                    # 提取漏洞信息，从content字段获取所有漏洞
                    vulnerabilities = intel_data.get("content", [])
                    
                    # 筛选并格式化漏洞信息
                    cves = []
                    for vuln in vulnerabilities:
                        log_info(f"处理安天漏洞: {vuln.get('title', '无标题')}")
                        # 从漏洞标题中提取漏洞编号（位于括号内）
                        vuln_title = vuln.get("title", "")
                        cve_info = self.to_cve(vuln, intel_data)
                        if cve_info.is_valid():
                            cves.append(cve_info)
                            log_info(f"提取到漏洞编号: {cve_info.cve}")
                    
                    # 过滤已经存在于数据库的威胁情报
                    filtered_cves = []
                    for cve in cves:
                        if hasattr(cve, 'id') and cve.id and not is_vulnerability_exists(cve.id):
                            filtered_cves.append(cve)
                            log_info(f"发现新安天威胁情报：{cve.title}，ID：{cve.id}")
                        else:
                            if hasattr(cve, 'title'):
                                log_info(f"安天威胁情报已存在于数据库中，跳过：{cve.title}")
                    
                    log_info(f"从安天获取到 {len(filtered_cves)}/{len(cves)} 条新威胁情报")
                    return filtered_cves
                else:
                    log_error(f"API返回状态不是success，状态为：{data.get('status')}")
                    return []
            else:
                log_error(f"API请求失败，状态码：{response.status_code}")
                return []
        except Exception as e:
            log_error(f"获取 [{self.NAME_CH()}] 威胁情报异常: {str(e)}")
            log_error(traceback.format_exc())
            return []

    def to_cve(self, vuln, intel_data):
        """
        将安天API返回的数据转为CVEInfo对象
        :param vuln: 单个漏洞数据
        :param intel_data: 完整情报数据
        :return: CVEInfo对象
        """
        cve = CVEInfo()
        
        # 处理标题，先获取title
        title = vuln.get("title", "")
        log_info(f"正在处理漏洞: {title}")
        
        # 提取ID，如果为空则生成一个
        extracted_id = self.extract_ids_from_title(title)
        log_info(f"从标题 '{title}' 中提取到的ID: {extracted_id}")
        
        if not extracted_id:
            # 生成唯一ID
            time_str = intel_data.get("time", "")
            unique_str = f"{title}-{time_str}-{datetime.now().timestamp()}"
            cve.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
            log_info(f"未找到ID，生成MD5: {cve.id}")
        else:
            cve.id = extracted_id
            log_info(f"使用提取的ID: {extracted_id}")
            
        # 设置基本属性
        cve.title = title
        cve.time = intel_data.get("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        cve.cve = extracted_id
        cve.src = self.NAME_CH()
        
        # 设置URL，使用当前日期而不是固定时间戳
        # 从intel_data中提取日期，格式通常为 "2025-05-15 ..."
        if "time" in intel_data and intel_data["time"]:
            try:
                # 尝试从时间字符串中提取日期部分
                date_part = intel_data["time"].split()[0].replace("-", "")  # "2025-05-15" -> "20250515"
                cve.url = f"https://www.antiycloud.com/#/infodetail/{date_part}"
            except Exception:
                # 如果提取失败，使用当前日期
                current_date = datetime.now().strftime("%Y%m%d")
                cve.url = f"https://www.antiycloud.com/#/infodetail/{current_date}"
        else:
            # 如果没有时间信息，使用当前日期
            current_date = datetime.now().strftime("%Y%m%d")
            cve.url = f"https://www.antiycloud.com/#/infodetail/{current_date}"
            
        cve.detail_url = cve.url  # 确保 detail_url 有值
        cve.source = self.NAME_CH()
        
        # 尝试提取漏洞描述
        try:
            if "body" in vuln and isinstance(vuln["body"], list):
                for section in vuln["body"]:
                    if section.get("subtitle") == "一、漏洞描述：":
                        content_list = section.get("content", [])
                        description_texts = []
                        for content_item in content_list:
                            if content_item.get("type") == "text":
                                description_texts.append(content_item.get("data", ""))
                        if description_texts:
                            cve.info = " ".join(description_texts)
        except Exception as e:
            log_error(f"提取漏洞描述时出错: {e}")
            cve.info = f"漏洞标题: {title}"
        
        return cve
        

    def extract_ids_from_title(self, title):
        """
        从标题中提取漏洞编号（括号内的内容）
        :param title: 漏洞标题，例如"1 Tenda AC9命令注入漏洞（CVE-2025-45042）"
        :return: 提取到的漏洞编号，例如"CVE-2025-45042"
        """
        # 使用正则表达式提取标题中括号内的内容
        ids = re.findall(r'（(.*?)）|\((.*?)\)', title)
        # 处理正则表达式结果，ids可能是[('CVE-2025-45042', '')] 或 [('', 'CVE-2025-45042')]形式
        result = []
        for id_pair in ids:
            # 检查每个分组是否有值，取非空的那个
            for id_val in id_pair:
                if id_val:
                    result.append(id_val)
        
        # 返回结果
        return ', '.join(result) if result else ""

class Tenable(BaseCrawler):
    """
    Tenable 漏洞信息爬虫
    """

    def __init__(self):
        """
        初始化
        """
        super().__init__(timeout=60)
        self.url = 'https://www.tenable.com/cve/feeds?sort=newest'

    def NAME_CH(self):
        return 'Tenable (Nessus)'

    def NAME_EN(self):
        return 'Tenable'

    def get_cves(self, limit=10):
        response = requests.get(
            self.url,
            headers=self.headers(),
            timeout=self.timeout
        )

        cves = []
        if response.status_code == 200:
            data = ''.join(response.text.split('\n')[1:])
            rss = etree.XML(data)
            items = rss.xpath("//item")

            cnt = 0
            for item in items:
                cve = self.to_cve(item)
                if cve.is_valid():
                    if cnt < limit:
                        cves.append(cve)
                        cnt += 1
        else:
            log_warn('获取 [%s] 威胁情报失败： [HTTP Error %i]' % (self.NAME_CH(), response.status_code))
        return cves

    def to_cve(self, item):
        cve = CVEInfo()
        
        # 获取ID，如果为空则生成一个唯一ID
        title_text = item.xpath("./title")[0].text if item.xpath("./title") else ""
        if title_text:
            cve.id = title_text
        else:
            # 生成一个唯一ID
            _time = item.xpath("./pubDate")[0].text if item.xpath("./pubDate") else ""
            unique_str = f"tenable-{_time}-{datetime.now().timestamp()}"
            cve.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
            
        cve.title = title_text if title_text else "Tenable漏洞"
        cve.src = self.NAME_CH()
        
        link_text = item.xpath("./link")[0].text if item.xpath("./link") else ""
        cve.url = link_text if link_text else ""
        cve.detail_url = cve.url  # 确保 detail_url 有值

        _time = item.xpath("./pubDate")[0].text if item.xpath("./pubDate") else ""
        if _time:
            try:
                cve.time = datetime.strptime(_time, '%a, %d %b %Y %H:%M:%S GMT').strftime('%Y-%m-%d %H:%M:%S')
            except:
                cve.time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        else:
            cve.time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 提取描述信息
        if item.xpath("./description"):
            _desc = item.xpath("./description")[0].text
            _desc = _desc.replace('\r', '').replace('\n', '') if _desc else ""
            try:
                cve.info = re.findall(r'Description</h3>\s*<p>(.*?)</p>', _desc, re.DOTALL)[0].strip()
            except:
                cve.info = _desc
            cve.title = cve.info if cve.info else cve.title
        else:
            cve.info = cve.title
            
        cve.source = self.NAME_CH()
        return cve

class MicrosoftSecurityCrawler(BaseCrawler):
    """
    微软安全响应中心漏洞信息爬虫
    """

    def __init__(self):
        """
        初始化
        """
        super().__init__(timeout=60)
        self.ms_url = 'https://api.msrc.microsoft.com/sug/v2.0/zh-CN/vulnerability'

    def NAME_CH(self):
        return '微软安全响应中心'

    def NAME_EN(self):
        return 'Microsoft Security'

    def get_vulnerabilities(self):
        """虚拟实现，不使用"""
        return []

    def get_cves(self):
        """
        获取微软安全响应中心最新漏洞信息
        :return: 漏洞信息列表
        """
        try:
            log_info("正在从微软安全响应中心获取数据...")
            header = {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
                'Connection': 'keep-alive',
            }
            
            response = requests.get(self.ms_url, headers=header, timeout=self.timeout)
            
            if response.status_code != 200:
                log_error(f"微软安全响应中心API请求失败，状态码: {response.status_code}")
                return []
                
            json_data = response.json()
            
            if '@odata.count' in json_data:
                log_info(f"微软安全响应中心API返回数据总量: {json_data['@odata.count']} 条")
            
            # 获取当天日期
            today = datetime.now().strftime('%Y-%m-%d')
            log_info(f"使用当前日期 {today} 过滤微软安全响应中心漏洞")
            
            # 筛选今天发布的漏洞
            all_cves = []
            new_cves = []
            
            if 'value' in json_data:
                for item in json_data['value']:
                    if 'releaseDate' in item:
                        # releaseDate格式如 "2025-03-21T07:00:43Z"，我们只需要比较日期部分
                        release_date = item['releaseDate'].split('T')[0]  # 提取日期部分 "2025-03-21"
                        # 只筛选当天的数据
                        if release_date == today:
                            cve_info = self.to_cve(item)
                            if cve_info.is_valid():
                                all_cves.append(cve_info)
                                
            # 过滤已存在于数据库的漏洞
            for cve in all_cves:
                if not is_vulnerability_exists(cve.id):
                    new_cves.append(cve)
                    log_info(f"发现新的微软漏洞: {cve.title}")
                else:
                    log_info(f"微软漏洞已存在，跳过: {cve.title}")
            
            log_info(f"从微软安全响应中心获取到 {len(new_cves)}/{len(all_cves)} 条新漏洞数据")
            return new_cves
        except Exception as e:
            log_error(f"获取微软安全响应中心数据时出错: {e}")
            return []

    def to_cve(self, item):
        """
        将微软API返回的数据转为CVEInfo对象
        :param item: API返回的单条数据
        :return: CVEInfo对象
        """
        cve = CVEInfo()
        
        # 获取ID，如果为空则生成一个唯一ID
        cve_number = item.get('cveNumber', '')
        if cve_number:
            cve.id = cve_number
        else:
            # 使用标题和时间生成唯一ID
            title = item.get('cveTitle', '无标题')
            release_date = ''
            if 'releaseDate' in item:
                release_date = item['releaseDate'].split('T')[0]
            unique_str = f"ms-{title}-{release_date}-{datetime.now().timestamp()}"
            cve.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
            
        cve.title = item.get('cveTitle', '无标题')
        
        # 处理时间 "2025-03-21T07:00:43Z" -> "2025-03-21"
        if 'releaseDate' in item:
            release_date = item['releaseDate'].split('T')[0]
            cve.time = release_date
        else:
            cve.time = datetime.now().strftime('%Y-%m-%d')
        
        cve.cve = item.get('cveNumber', '无CVE编号')
        cve.src = self.NAME_CH()
        
        # 获取URL
        mitre_url = item.get('mitreUrl', '')
        if mitre_url:
            cve.url = mitre_url
        else:
            cve_number = item.get('cveNumber', '')
            if cve_number:
                cve.url = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_number}"
            else:
                cve.url = "https://msrc.microsoft.com/update-guide/"
                
        cve.detail_url = cve.url  # 确保 detail_url 有值
        cve.source = self.NAME_CH()
        cve.info = item.get('unformattedDescription', item.get('description', '无描述'))
        
        return cve

class OKCVECrawler(BaseCrawler):
    """
    CVE漏洞库爬虫类
    """

    def __init__(self):
        super(OKCVECrawler, self).__init__()
        # CVE漏洞库API地址
        self.json_url = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/deltaLog.json'

    def NAME_CH(self):
        return 'CVE漏洞库'

    def NAME_EN(self):
        return 'OKCVE'

    def get_vulnerabilities(self):
        return []  # 使用get_cves方法获取漏洞信息

    def get_cves(self):
        """
        从CVE漏洞库获取最新CVE信息
        :return: 漏洞信息列表
        """
        try:
            log_info(f"[{self.NAME_CH()}] 开始获取最新CVE信息")
            
            # 加载运行配置，获取GitHub token
            run_config = load_run_config()
            github_token = run_config.get('github_token', '')
            
            # 从URL获取JSON数据，添加GitHub token用于认证
            headers = {}
            if github_token:
                headers['Authorization'] = f'token {github_token}'
                log_info(f"[{self.NAME_CH()}] 使用GitHub token进行API请求")
            
            response = requests.get(self.json_url, headers=headers)
            response.raise_for_status()  # 检查HTTP错误
            data = response.json()
            
            # 获取当前日期，确保使用最新日期
            current_date = datetime.now().strftime('%Y-%m-%d')
            log_info(f"[{self.NAME_CH()}] 使用当前日期 {current_date} 过滤CVE信息")
            
            all_cve_list = []
            
            # 处理数据
            for entry in data:
                fetch_time = entry.get('fetchTime', '')
                if fetch_time.startswith(f'{current_date}T'):
                    for cve in entry.get('new', []):
                        cve_info = self.to_cve(cve, fetch_time)
                        if cve_info.is_valid():
                            all_cve_list.append(cve_info)
            
            # 过滤已经存在于数据库的CVE
            new_cve_list = []
            for cve_info in all_cve_list:
                if not is_vulnerability_exists(cve_info.id):
                    new_cve_list.append(cve_info)
                    log_info(f"发现新CVE: {cve_info.title}")
                else:
                    log_info(f"CVE已存在，跳过: {cve_info.title}")
            
            log_info(f"[{self.NAME_CH()}] 获取到 {len(new_cve_list)}/{len(all_cve_list)} 条新CVE信息")
            return new_cve_list
        except Exception as e:
            log_error(f"[{self.NAME_CH()}] 获取CVE信息失败: {str(e)}")
            return []

    def to_cve(self, cve_data, fetch_time):
        """
        转换CVE数据为CVEInfo对象
        :param cve_data: CVE数据
        :param fetch_time: 抓取时间
        :return: CVEInfo对象
        """
        info = CVEInfo()
        
        # 获取ID，如果为空则生成一个唯一ID
        cve_id = cve_data.get('cveId', '')
        if cve_id:
            info.id = cve_id
        else:
            # 生成唯一ID
            unique_str = f"cve-{fetch_time}-{datetime.now().timestamp()}"
            info.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
            
        # 设置标题
        if cve_id:
            info.title = f"{cve_id}漏洞"
        else:
            info.title = f"未知CVE漏洞-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
        info.time = fetch_time if fetch_time else datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        info.cve = cve_id if cve_id else '未知CVE'
        info.src = self.NAME_CH()
        
        # 设置URL
        cve_org_link = cve_data.get('cveOrgLink', '')
        if cve_org_link:
            info.url = cve_org_link
        elif cve_id:
            info.url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        else:
            info.url = "https://cve.mitre.org/"
            
        info.detail_url = info.url  # 确保 detail_url 有值
        info.source = self.NAME_CH()
        info.info = ''
        return info

class QianxinCrawler(BaseCrawler):
    """
    奇安信CERT爬虫类
    """

    def __init__(self):
        super(QianxinCrawler, self).__init__()
        # 奇安信API地址
        self.api_url = 'https://ti.qianxin.com/alpha-api/v2/vuln/one-day'
        # 要“中危”也算就在这里加
        self.level_ok = {"高危", "极危", "严重"}

    def NAME_CH(self):
        return '奇安信CERT'

    def NAME_EN(self):
        return 'Qianxin CERT'

    def get_vulnerabilities(self):
        return []  # 使用get_cves方法获取漏洞信息

    def get_cves(self):
        """
        从奇安信CERT获取最新漏洞信息
        :return: 漏洞信息列表
        """
        try:
            log_info(f"[{self.NAME_CH()}] 开始获取最新漏洞信息")
            
            # 获取当前日期
            current_date = datetime.now().strftime('%Y-%m-%d')
            log_info(f"[{self.NAME_CH()}] 使用当前日期 {current_date} 过滤漏洞信息")
            
            # 发送请求
            response = requests.get(
                self.api_url,
                headers=self.headers(),
                params={"date": current_date},
                timeout=self.timeout
            )
            response.raise_for_status()  # 检查HTTP错误
            data = response.json()
            
            # 提取漏洞信息
            all_cve_list = []
            rows = self._collect_rows(data)
            
            for row in rows:
                pub_date = row.get("publish_time") or row.get("date") or ""
                if pub_date == current_date:
                    level = self._pick_level(row)
                    if level in self.level_ok:
                        cve_info = self.to_cve(row)
                        if cve_info.is_valid():
                            all_cve_list.append(cve_info)
            
            # 过滤已经存在于数据库的漏洞
            new_cve_list = []
            for cve_info in all_cve_list:
                if not is_vulnerability_exists(cve_info.id):
                    new_cve_list.append(cve_info)
                    log_info(f"发现新奇安信漏洞: {cve_info.title}")
                else:
                    log_info(f"奇安信漏洞已存在，跳过: {cve_info.title}")
            
            log_info(f"[{self.NAME_CH()}] 获取到 {len(new_cve_list)}/{len(all_cve_list)} 条新漏洞信息")
            return new_cve_list
        except Exception as e:
            log_error(f"[{self.NAME_CH()}] 获取漏洞信息失败: {str(e)}")
            return []

    def _collect_rows(self, obj):
        """把 one-day 返回的五个列表合并"""
        rows = []
        data = obj.get("data", {})
        for key in ("vuln_add", "vuln_update", "key_vuln_add",
                    "poc_exp_add", "patch_add"):
            val = data.get(key)
            if isinstance(val, list):
                rows.extend(val)
        return rows

    def _pick_level(self, row):
        """不同接口的严重度字段兜底"""
        for k in ("rating_level", "level", "risk_level", "rating_level_cn"):
            if row.get(k):
                return row[k]
        return "未知"

    def to_cve(self, item):
        """
        转换奇安信API返回的数据为CVEInfo对象
        :param item: 单个漏洞数据
        :return: CVEInfo对象
        """
        cve = CVEInfo()
        
        # 获取ID，如果为空则生成一个唯一ID
        cve_id = item.get("cve_code") or item.get("cve_id") or ""
        if cve_id:
            cve.id = cve_id
        else:
            # 生成唯一ID
            title = item.get("vuln_name") or item.get("title") or ""
            time_str = item.get("publish_time") or item.get("date") or ""
            unique_str = f"qianxin-{title}-{time_str}-{datetime.now().timestamp()}"
            cve.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
            
        # 设置基本属性
        cve.title = item.get("vuln_name") or item.get("title") or "未知漏洞"
        cve.time = item.get("publish_time") or item.get("date") or datetime.now().strftime("%Y-%m-%d")
        cve.cve = cve_id
        cve.src = self.NAME_CH()
        
        # 设置URL
        cve.url = f"https://ti.qianxin.com/vulnerability/{cve_id}" if cve_id else "https://ti.qianxin.com/"
        cve.detail_url = cve.url  # 确保 detail_url 有值
        cve.source = self.NAME_CH()
        cve.info = item.get("description", "")
        
        return cve

class ThreatBookCrawler(BaseCrawler):
    """
    微步爬虫类
    """

    def __init__(self):
        super(ThreatBookCrawler, self).__init__()
        # 微步API地址
        self.api_url = 'https://x.threatbook.com/v5/node/vul_module/homePage'
        # 微步请求头
        self._headers = {
            "Referer": "https://x.threatbook.com/",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "User-Agent": "Mozilla/5.0",
        }

    def NAME_CH(self):
        return '微步'

    def NAME_EN(self):
        return 'ThreatBook'

    def get_vulnerabilities(self):
        return []  # 使用get_cves方法获取漏洞信息

    def get_cves(self):
        """
        从微步获取最新漏洞信息
        :return: 漏洞信息列表
        """
        try:
            log_info(f"[{self.NAME_CH()}] 开始获取最新漏洞信息")
            
            # 获取当前日期
            current_date = datetime.now().strftime('%Y-%m-%d')
            log_info(f"[{self.NAME_CH()}] 使用当前日期 {current_date} 过滤漏洞信息")
            
            # 发送请求
            response = requests.get(
                self.api_url,
                headers=self._headers,
                timeout=self.timeout
            )
            response.raise_for_status()  # 检查HTTP错误
            data = response.json()
            
            # 提取漏洞信息
            all_cve_list = []
            
            for key in ("premium", "highRisk"):
                for it in data.get("data", {}).get(key, []):
                    item = self._to_cve(it)
                    if item and item.time == current_date:
                        all_cve_list.append(item)
            
            # 过滤已经存在于数据库的漏洞
            new_cve_list = []
            for cve_info in all_cve_list:
                if not is_vulnerability_exists(cve_info.id):
                    new_cve_list.append(cve_info)
                    log_info(f"发现新微步漏洞: {cve_info.title}")
                else:
                    log_info(f"微步漏洞已存在，跳过: {cve_info.title}")
            
            log_info(f"[{self.NAME_CH()}] 获取到 {len(new_cve_list)}/{len(all_cve_list)} 条新漏洞信息")
            return new_cve_list
        except Exception as e:
            log_error(f"[{self.NAME_CH()}] 获取漏洞信息失败: {str(e)}")
            return []

    def _to_cve(self, it):
        """
        转换微步API返回的数据为CVEInfo对象
        :param it: 单个漏洞数据
        :return: CVEInfo对象或None
        """
        ts = it.get("vuln_update_time") or it.get("vulnPublishTime")
        if not ts:
            return None
            
        cve = CVEInfo()
        cve_id = it.get("id") or ""
        
        # 获取ID，如果为空则生成一个唯一ID
        if cve_id:
            cve.id = cve_id
        else:
            # 生成唯一ID
            title = it.get("vuln_name_zh") or it.get("vulnNameZh") or it.get("title", "")
            unique_str = f"threatbook-{title}-{ts}-{datetime.now().timestamp()}"
            cve.id = hashlib.md5(unique_str.encode('utf-8')).hexdigest()
            
        # 设置基本属性
        cve.title = it.get("vuln_name_zh") or it.get("vulnNameZh") or it.get("title", "未知漏洞")
        cve.time = ts[:10]  # 仅取 'YYYY-MM-DD'
        cve.cve = cve_id
        cve.src = self.NAME_CH()
        
        # 设置URL
        cve.url = f"https://x.threatbook.com/v5/vuln/detail/{cve_id}" if cve_id else "https://x.threatbook.com/"
        cve.detail_url = cve.url  # 确保 detail_url 有值
        cve.source = self.NAME_CH()
        cve.info = it.get("description", "")
        
        return cve

# 读取配置文件

def load_config():
    try:
        log_info("开始读取配置文件...")
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
            log_info("配置文件读取成功")
        
        # 优先从环境变量读取配置
        def get_env_or_config(env_name, config_path, default=''):
            """从环境变量或配置文件获取值"""
            return os.environ.get(env_name, config_path if config_path else default)
        
        # 检查钉钉配置
        if int(config['all_config']['dingding'][0]['enable']) == 1:
            # 从环境变量或配置文件获取值
            dingding_webhook = get_env_or_config('DINGDING_WEBHOOK', config['all_config']['dingding'][1]['webhook'])
            dingding_secretKey = get_env_or_config('DINGDING_SECRET', config['all_config']['dingding'][2]['secretKey'])
            app_name = config['all_config']['dingding'][3]['app_name']
            log_info(f"启用钉钉推送，webhook长度: {len(dingding_webhook)}, secretKey长度: {len(dingding_secretKey)}")
            return app_name, dingding_webhook, dingding_secretKey
        
        # 检查飞书配置
        elif int(config['all_config']['feishu'][0]['enable']) == 1:
            feishu_webhook = get_env_or_config('FEISHU_WEBHOOK', config['all_config']['feishu'][1]['webhook'])
            app_name = config['all_config']['feishu'][2]['app_name']
            log_info(f"启用飞书推送，webhook长度: {len(feishu_webhook)}")
            return app_name, feishu_webhook
        
        # 检查Telegram配置
        elif int(config['all_config']['tgbot'][0]['enable']) == 1:
            tgbot_token = get_env_or_config('TELEGRAM_TOKEN', config['all_config']['tgbot'][1]['token'])
            tgbot_group_id = get_env_or_config('TELEGRAM_GROUP_ID', config['all_config']['tgbot'][2]['group_id'])
            app_name = config['all_config']['tgbot'][3]['app_name']
            log_info(f"启用Telegram推送，token长度: {len(tgbot_token)}, group_id: {tgbot_group_id}")
            return app_name, tgbot_token, tgbot_group_id
        
        # 检查Discard配置
        elif int(config['all_config']['discard'][0]['enable']) == 1:
            discard_webhook = get_env_or_config('DISCARD_WEBHOOK', config['all_config']['discard'][1]['webhook'])
            app_name = config['all_config']['discard'][2]['app_name']
            # 新增：获取send_normal_msg和send_daily_report配置
            send_normal_msg = get_env_or_config('DISCARD_SEND_NORMAL_MSG', config['all_config']['discard'][3].get('send_normal_msg', 'ON'))
            send_daily_report = get_env_or_config('DISCARD_SEND_DAILY_REPORT', config['all_config']['discard'][4].get('send_daily_report', 'ON'))
            log_info(f"启用Discard推送，webhook长度: {len(discard_webhook)}, 每日推送: {send_normal_msg}, 周报推送: {send_daily_report}")
            return app_name, discard_webhook, send_normal_msg, send_daily_report
        
        # 没有启用任何推送
        elif (int(config['all_config']['tgbot'][0]['enable']) == 0 and
              int(config['all_config']['feishu'][0]['enable']) == 0 and
              int(config['all_config']['dingding'][0]['enable']) == 0 and
              int(config['all_config']['discard'][0]['enable']) == 0):
            log_error("配置文件有误, 所有社交软件的enable都为0")
            return None
    except Exception as e:
        log_error(f"读取配置文件失败: {e}")
        log_error(traceback.format_exc())
        return None

# 加载翻译配置
def load_translate_config():
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
            translate_config = config.get('all_config', {}).get('translate', [])
            
            # 构建翻译配置字典
            translate_dict = {}
            for item in translate_config:
                for key, value in item.items():
                    translate_dict[key] = value
            
            return translate_dict
    except Exception as e:
        log_error(f"读取翻译配置失败: {e}")
        return None

# 加载运行配置
def load_run_config():
    """加载运行配置"""
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
        
        # 从配置文件获取运行配置
        run_config = config.get('all_config', {}).get('run_config', [])
        
        # 构建运行配置字典
        run_dict = {}
        for item in run_config:
            for key, value in item.items():
                run_dict[key] = value
        
        # 优先从环境变量读取配置
        # 环境变量优先级高于配置文件
        run_dict['enable_night_sleep'] = int(os.environ.get('ENABLE_NIGHT_SLEEP', run_dict.get('enable_night_sleep', 1)))
        run_dict['night_sleep_start'] = int(os.environ.get('NIGHT_SLEEP_START', run_dict.get('night_sleep_start', 0)))
        run_dict['night_sleep_end'] = int(os.environ.get('NIGHT_SLEEP_END', run_dict.get('night_sleep_end', 7)))
        run_dict['check_interval'] = int(os.environ.get('CHECK_INTERVAL', run_dict.get('check_interval', 7200)))
        run_dict['max_run_time'] = int(os.environ.get('MAX_RUN_TIME', run_dict.get('max_run_time', 3540)))
        run_dict['exception_retry_interval'] = int(os.environ.get('EXCEPTION_RETRY_INTERVAL', run_dict.get('exception_retry_interval', 60)))
        run_dict['github_token'] = os.environ.get('GITHUB_TOKEN', run_dict.get('github_token', ''))
        
        return run_dict
    except Exception as e:
        log_error(f"加载运行配置失败: {e}")
        log_error(traceback.format_exc())
        # 返回默认配置
        return {
            'enable_night_sleep': 1,
            'night_sleep_start': 0,
            'night_sleep_end': 7,
            'check_interval': 7200,
            'max_run_time': 3540,
            'exception_retry_interval': 60,
            'github_token': ''
        }

# 加载数据源配置
def load_datasource_config():
    """加载数据源配置"""
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
        
        # 从配置文件获取数据源配置
        datasource_config = config.get('all_config', {}).get('datasources', [])
        
        # 构建数据源配置字典
        datasource_dict = {
            'oscs1024': 1,
            'antiycloud': 1,
            'tenable': 1,
            'microsoft': 1,
            'okcve': 1,
            'qianxin': 1,
            'threatbook': 1
        }
        
        for item in datasource_config:
            for key, value in item.items():
                datasource_dict[key] = value
        
        # 优先从环境变量读取配置
        # 环境变量优先级高于配置文件
        datasource_dict['oscs1024'] = int(os.environ.get('DATASOURCE_OSCS1024', datasource_dict.get('oscs1024', 1)))
        datasource_dict['antiycloud'] = int(os.environ.get('DATASOURCE_ANTIYCLOUD', datasource_dict.get('antiycloud', 1)))
        datasource_dict['tenable'] = int(os.environ.get('DATASOURCE_TENABLE', datasource_dict.get('tenable', 1)))
        datasource_dict['microsoft'] = int(os.environ.get('DATASOURCE_MICROSOFT', datasource_dict.get('microsoft', 1)))
        datasource_dict['okcve'] = int(os.environ.get('DATASOURCE_OKCVE', datasource_dict.get('okcve', 1)))
        datasource_dict['qianxin'] = int(os.environ.get('DATASOURCE_QIANXIN', datasource_dict.get('qianxin', 1)))
        datasource_dict['threatbook'] = int(os.environ.get('DATASOURCE_THREATBOOK', datasource_dict.get('threatbook', 1)))
        
        return datasource_dict
    except Exception as e:
        log_error(f"加载数据源配置失败: {e}")
        log_error(traceback.format_exc())
        # 返回默认配置
        return {
            'oscs1024': 1,
            'antiycloud': 1,
            'tenable': 1,
            'microsoft': 1,
            'okcve': 1,
            'qianxin': 1,
            'threatbook': 1
        }

# 检查是否是夜间时间
def is_night_time(run_config):
    """检查是否是夜间时间"""
    if not run_config.get('enable_night_sleep', 1):
        return False
    
    current_hour = datetime.now().hour
    start_hour = run_config.get('night_sleep_start', 0)
    end_hour = run_config.get('night_sleep_end', 7)
    
    return start_hour <= current_hour < end_hour

# 翻译函数
def translate_text(text, source_lang='en', target_lang='zh-cn'):
    """
    翻译文本
    :param text: 要翻译的文本
    :param source_lang: 源语言
    :param target_lang: 目标语言
    :return: 翻译后的文本
    """
    if not text or not isinstance(text, str) or len(text.strip()) == 0:
        return text
    
    try:
        # 尝试导入googletrans库
        from googletrans import Translator
        
        translator = Translator()
        result = translator.translate(text, src=source_lang, dest=target_lang)
        return result.text
    except ImportError:
        log_warn("googletrans库未安装，跳过翻译")
        return text
    except Exception as e:
        log_error(f"翻译失败: {e}")
        return text

# 初始化创建数据库
def create_database():
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    try:
        cur.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                   (id TEXT PRIMARY KEY,
                    title TEXT,
                    time TEXT,
                    source TEXT,
                    detail_url TEXT,
                    cve_ids TEXT)''')
        conn.commit()
    except Exception as e:
        print("创建监控表失败！报错：{}".format(e))
    conn.close()

# 检查漏洞是否已存在
def is_vulnerability_exists(cve_id):
    # 如果ID为空，直接返回True表示已存在，防止插入空ID记录
    if not cve_id or cve_id.strip() == '':
        return True
        
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM vulnerabilities WHERE id = ?", (cve_id,))
        result = cur.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        log_error(f"检查漏洞是否存在时出错：{e}")
        conn.close()
        return False

# 将已过滤的漏洞信息插入到数据库（不再检查是否存在）
def insert_into_sqlite3_without_check(cve_list):
    """
    将漏洞信息插入到数据库并立即推送，不再检查是否存在
    因为调用此函数之前已经过滤掉数据库中存在的记录
    :param cve_list: 漏洞信息列表
    """
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    insert_count = 0
    error_count = 0
    
    # 获取配置信息用于推送
    try:
        config = load_config()
        can_push = bool(config)
        if can_push:
            app_name = config[0]
            log_info(f"获取到推送配置，使用 {app_name} 服务")
        else:
            log_warn("未获取到有效的推送配置，将只进行数据库插入，不推送消息")
    except Exception as e:
        log_error(f"加载推送配置失败: {e}")
        can_push = False
    
    # 加载翻译配置
    translate_config = load_translate_config()
    translate_enabled = translate_config and int(translate_config.get('enable', 0)) == 1
    if translate_enabled:
        source_lang = translate_config.get('source_lang', 'en')
        target_lang = translate_config.get('target_lang', 'zh-cn')
        log_info(f"启用翻译功能，源语言: {source_lang}，目标语言: {target_lang}")
    
    for cve in cve_list:
        try:
            # 确保id不为空且有效
            if hasattr(cve, 'id') and cve.id and cve.id.strip() != '':
                id = cve.id
                title = cve.title if hasattr(cve, 'title') and cve.title else '无标题'
                time = cve.time if hasattr(cve, 'time') and cve.time else datetime.now().strftime('%Y-%m-%d')
                source = cve.src if hasattr(cve, 'src') and cve.src else '未知来源'
                detail_url = getattr(cve, 'detail_url', '')  # 使用 getattr 避免除错
                cve_ids = cve.cve if hasattr(cve, 'cve') and cve.cve else ''
                
                # 翻译处理
                translated_title = title
                if translate_enabled:
                    translated_title = translate_text(title, source_lang, target_lang)
                    # 如果有描述信息，也进行翻译
                    if hasattr(cve, 'info') and cve.info:
                        cve.info = translate_text(cve.info, source_lang, target_lang)
                
                # 插入数据库
                cur.execute("INSERT INTO vulnerabilities (id, title, time, source, detail_url, cve_ids) VALUES (?, ?, ?, ?, ?, ?)",
                           (id, translated_title, time, source, detail_url, cve_ids))
                conn.commit()  # 每插入一条就提交一次，确保数据立即保存
                insert_count += 1
                log_info(f"插入新漏洞成功：{translated_title}")
                
                # 立即推送该条漏洞信息
                if can_push:
                    # 构造推送信息
                    push_text = '发现新漏洞！'
                    
                    # 构造通用链接
                    cve_url = getattr(cve, 'detail_url', '')  # 使用 getattr 避免除错
                    if not cve_url and hasattr(cve, 'cve') and cve.cve:
                        cve_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.cve}"
                    
                    # 获取漏洞编号
                    if hasattr(cve, 'cve') and cve.cve:
                        vuln_id = cve.cve
                    elif hasattr(cve, 'ids') and cve.ids:
                        vuln_id = ', '.join(cve.ids)
                    else:
                        vuln_id = cve.id
                    
                    # 格式化来源，确保显示正确
                    formatted_source = source
                    if source == 'Tenable':
                        formatted_source = 'Tenable (Nessus)'
                    elif source == '微步':
                        formatted_source = '微步（ThreatBook）'
                    
                    # 构造推送消息，格式与示例完全一致
                    push_msg = f"漏洞标题: {translated_title}\n漏洞编号: {vuln_id}\n来源: {formatted_source}\n时间: {time}"
                    if cve_url:
                        push_msg += f"\n详情链接: {cve_url}"
                    # 如果有翻译后的描述信息，也添加到推送内容中
                    if hasattr(cve, 'info') and cve.info:
                        push_msg += f"\n漏洞描述: {cve.info}"
                    
                    # 根据配置的推送方式发送消息
                    try:
                        push_result = False
                        if app_name == "dingding":
                            push_result = dingding(push_text, push_msg, config[1], config[2])
                            log_info(f"钉钉推送结果: {'成功' if push_result else '失败'} - {translated_title}")
                        elif app_name == "feishu":
                            push_result = feishu(push_text, push_msg, config[1])
                            log_info(f"飞书推送结果: {'成功' if push_result else '失败'} - {translated_title}")
                        elif app_name == "tgbot":
                            push_result = tgbot(push_text, push_msg, config[1], config[2])
                            log_info(f"Telegram推送结果: {'成功' if push_result else '失败'} - {translated_title}")
                        elif app_name == "discard":
                            # 检查是否启用每日推送
                            send_normal_msg = config[2] if len(config) > 2 else 'ON'
                            # 确保send_normal_msg是字符串类型
                            send_normal_msg_str = str(send_normal_msg).upper()
                            if send_normal_msg_str == 'ON':
                                push_result = discard(push_text, push_msg, config[1])
                                log_info(f"Discard推送结果: {'成功' if push_result else '失败'} - {translated_title}")
                            else:
                                log_info(f"Discard每日推送已禁用，跳过推送: {translated_title}")
                                push_result = True
                        else:
                            log_warn(f"未知的推送方式: {app_name}")
                    except Exception as e:
                        log_error(f"推送漏洞信息失败：{e}")
                
        except sqlite3.IntegrityError as e:
            # 如果遇到唯一性约束错误，记录日志但不中断程序
            log_warn(f"插入数据时唯一性约束错误（意外情况）：{getattr(cve, 'title', '无标题')}，错误：{e}")
            error_count += 1
        except Exception as e:
            log_error(f"插入数据失败：{e}")
            log_error(traceback.format_exc())
            error_count += 1
    
    conn.close()
    log_info(f"成功插入 {insert_count} 条漏洞记录，失败 {error_count} 条")

# 钉钉推送
from dingtalkchatbot.chatbot import DingtalkChatbot  # 从dingtalkchatbot.chatbot模块导入DingtalkChatbot类

def dingding(text, msg, webhook, secretKey):
    try:
        log_info(f"准备推送钉钉消息，webhook: {webhook[:20]}...，内容长度: {len(msg)}")
        ding = DingtalkChatbot(webhook, secret=secretKey)
        result = ding.send_text(msg='{}\r\n{}'.format(text, msg), is_at_all=False)
        log_info(f"钉钉推送返回结果: {result}")
        
        # 钉钉推送API返回格式: {'errcode': 0, 'errmsg': 'ok'}
        if isinstance(result, dict) and result.get('errcode') == 0:
            log_info("钉钉推送成功")
            return True
        else:
            log_error(f"钉钉推送返回异常结果: {result}")
            return False
    except Exception as e:
        log_error(f"钉钉推送出现异常: {e}")
        log_error(traceback.format_exc())
        return False

# 飞书推送
def feishu(text, msg, webhook):
    try:
        log_info(f"准备推送飞书消息，webhook: {webhook[:20]}...，内容长度: {len(msg)}")
        ding = DingtalkChatbot(webhook)
        result = ding.send_text(msg='{}\r\n{}'.format(text, msg), is_at_all=False)
        log_info(f"飞书推送返回结果: {result}")
        
        if isinstance(result, dict) and result.get('StatusCode') == 0:
            log_info("飞书推送成功")
            return True
        else:
            log_error(f"飞书推送返回异常结果: {result}")
            return False
    except Exception as e:
        log_error(f"飞书推送出现异常: {e}")
        log_error(traceback.format_exc())
        return False



# Telegram Bot推送
def tgbot(text, msg, token, group_id):
    try:
        log_info(f"准备推送Telegram消息，token: {token[:8]}...，group_id: {group_id}，内容长度: {len(msg)}")
        bot = telegram.Bot(token='{}'.format(token))
        result = bot.send_message(chat_id=group_id, text='{}\r\n{}'.format(text, msg))
        log_info(f"Telegram推送成功，消息ID: {result.message_id}")
        return True
    except Exception as e:
        log_error(f"Telegram推送出现异常: {e}")
        log_error(traceback.format_exc())
        return False

# Discard推送
def discard(text, msg, webhook, is_daily_report=False, html_file=None, markdown_content=None):
    try:
        log_info(f"准备推送Discard消息，webhook: {webhook[:20]}...，内容长度: {len(msg)}, 报告模式: {is_daily_report}")
        
        headers = {
            "Content-Type": "application/json;charset=utf-8"
        }
        
        if is_daily_report and html_file:
            # 推送报告（日报或周报），使用Discord Embed格式创建卡片
            # 生成GitHub Pages URL
            github_pages_url = f"https://adminlove520.github.io/CVE_monitor/{html_file}"
            
            # 确定报告类型前缀
            report_prefix = "Weekly_" if "Weekly_" in html_file else "Daily_"
            
            # 解析漏洞数量
            vuln_count = msg.split()[1] if len(msg.split()) > 1 else "0"
            
            # 创建Embed卡片
            data = {
                "embeds": [
                    {
                        "title": text,
                        "description": f"共收集到 {vuln_count} 个漏洞\n欢迎提交建议：[GitHub Issue](https://github.com/adminlove520/CVE_monitor/issues/new/choose)",
                        "url": github_pages_url,
                        "color": 16711680,  # 红色
                        "fields": [
                            {
                                "name": "报告链接",
                                "value": f"[{report_prefix}{datetime.now().strftime('%Y-%m-%d')}]({github_pages_url})",
                                "inline": False
                            }
                        ],
                        "footer": {
                            "text": "Power By 东方隐侠安全团队·Anonymous@ 隐侠安全客栈",
                            "icon_url": "https://www.dfyxsec.com/favicon.ico"
                        },
                        "timestamp": datetime.now().isoformat()
                    }
                ]
            }
        else:
            # 推送普通消息，使用Discord Embed格式创建卡片
            # 解析漏洞信息
            vuln_info = {}
            lines = msg.split('\n')
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    vuln_info[key.strip()] = value.strip()
            
            # 创建Embed卡片
            fields = []
            if vuln_info.get('漏洞标题'):
                fields.append({
                    "name": "漏洞标题",
                    "value": vuln_info['漏洞标题'],
                    "inline": False
                })
            if vuln_info.get('漏洞编号'):
                fields.append({
                    "name": "漏洞编号",
                    "value": vuln_info['漏洞编号'],
                    "inline": True
                })
            if vuln_info.get('来源'):
                fields.append({
                    "name": "来源",
                    "value": vuln_info['来源'],
                    "inline": True
                })
            if vuln_info.get('时间'):
                fields.append({
                    "name": "时间",
                    "value": vuln_info['时间'],
                    "inline": True
                })
            if vuln_info.get('详情链接'):
                fields.append({
                    "name": "详情链接",
                    "value": f"[查看详情]({vuln_info['详情链接']})",
                    "inline": False
                })
            
            data = {
                "embeds": [
                    {
                        "title": text,
                        "color": 16776960,  # 黄色
                        "fields": fields,
                        "footer": {
                            "text": "Power By 东方隐侠安全团队·Anonymous@ 隐侠安全客栈",
                            "icon_url": "https://www.dfyxsec.com/favicon.ico"
                        },
                        "timestamp": datetime.now().isoformat()
                    }
                ]
            }
        
        response = requests.post(webhook, json=data, headers=headers, timeout=10)
        
        # 处理不同的响应情况
        if response.status_code in [200, 204]:
            # 成功状态码
            if response.status_code == 204:
                # 204 No Content - 没有响应体，直接返回成功
                log_info(f"Discard推送成功，状态码: {response.status_code}")
                return True
            else:
                # 200 OK - 可能有响应体，尝试解析
                try:
                    response_text = response.text
                    if response_text:
                        # 只有当响应体不为空时才尝试解析JSON
                        json_response = response.json()
                        if isinstance(json_response, dict):
                            if json_response.get('ok') or 'id' in json_response:  # Discord Webhook返回id表示成功
                                log_info(f"Discard推送成功，状态码: {response.status_code}，响应: {json_response}")
                                return True
                            else:
                                log_warning(f"Discard推送返回非预期JSON: {json_response}")
                                return True  # 状态码200，即使JSON内容非预期也视为成功
                        else:
                            log_warning(f"Discard推送返回非JSON响应: {response_text}")
                            return True  # 状态码200，即使非JSON也视为成功
                    else:
                        # 响应体为空，返回成功
                        log_info(f"Discard推送成功，状态码: {response.status_code}，响应体为空")
                        return True
                except requests.exceptions.JSONDecodeError:
                    # JSON解析失败，但状态码200，视为成功
                    log_info(f"Discard推送成功，状态码: {response.status_code}，响应体非JSON格式")
                    log_debug(f"响应内容: {response.text}")
                    return True
        else:
            # 失败状态码
            log_error(f"Discard推送失败，状态码: {response.status_code}")
            log_error(f"响应内容: {response.text}")
            return False
    except Exception as e:
        log_error(f"Discard推送出现异常: {e}")
        log_error(traceback.format_exc())
        return False

# 发送漏洞信息到社交工具
def send_alerts(cve_list):
    try:
        config = load_config()
        if not config:
            log_error("加载配置文件失败，无法发送推送")
            return
            
        app_name = config[0]
        log_info(f"使用 {app_name} 服务推送漏洞信息")

        for cve in cve_list:
            # 确保漏洞有ID且不存在于数据库中
            if hasattr(cve, 'id') and cve.id and cve.id.strip() and not is_vulnerability_exists(cve.id):
                text = '有新的漏洞信息！'
                # 构造通用链接
                cve_url = getattr(cve, 'detail_url', '')  # 使用 getattr 避免除错
                if not cve_url and hasattr(cve, 'cve') and cve.cve:
                    cve_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.cve}"
                
                title = getattr(cve, 'title', '无标题')
                src = getattr(cve, 'src', '未知来源')
                time_str = getattr(cve, 'time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                
                # 获取漏洞编号
                if hasattr(cve, 'cve') and cve.cve:
                    vuln_id = cve.cve
                elif hasattr(cve, 'ids') and cve.ids:
                    vuln_id = ', '.join(cve.ids)
                else:
                    vuln_id = cve.id
                
                # 格式化来源，确保显示正确
                formatted_source = src
                if src == 'Tenable':
                    formatted_source = 'Tenable (Nessus)'
                elif src == '微步':
                    formatted_source = '微步（ThreatBook）'
                
                # 构造推送消息，格式与示例完全一致
                msg = f"漏洞标题: {title}\n漏洞编号: {vuln_id}\n来源: {formatted_source}\n时间: {time_str}"
                if cve_url:
                    msg += f"\n详情链接: {cve_url}"
                
                # 根据配置的推送方式发送消息
                try:
                    if app_name == "dingding":
                        dingding(text, msg, config[1], config[2])
                        log_info(f"成功通过钉钉推送漏洞信息：{title}")
                    elif app_name == "feishu":
                        feishu(text, msg, config[1])
                        log_info(f"成功通过飞书推送漏洞信息：{title}")
                    elif app_name == "tgbot":
                        tgbot(text, msg, config[1], config[2])
                        log_info(f"成功通过Telegram推送漏洞信息：{title}")
                    elif app_name == "discard":
                        # 检查是否启用每日推送
                        send_normal_msg = config[2] if len(config) > 2 else 'ON'
                        if send_normal_msg.upper() == 'ON':
                            discard(text, msg, config[1])
                            log_info(f"成功通过Discard推送漏洞信息：{title}")
                        else:
                            log_info(f"Discard每日推送已禁用，跳过推送: {title}")
                except Exception as e:
                    log_error(f"推送漏洞信息失败：{e}")
    except Exception as e:
        log_error(f"发送漏洞推送时出错：{e}")
        log_error(traceback.format_exc())

# 将漏洞信息插入到数据库，并立即推送新发现的漏洞
def insert_into_sqlite3(cve_list):
    """
    将漏洞信息插入到数据库并立即推送
    为保持向后兼容性保留此函数，但现在直接调用无检查版本
    :param cve_list: 漏洞信息列表
    """
    log_info("调用兼容性函数insert_into_sqlite3，内部使用无检查版本")
    # 直接调用无检查版本
    insert_into_sqlite3_without_check(cve_list)

# 生成日报
def generate_daily_report():
    """
    生成日报，包括Markdown和HTML格式
    """
    log_info("开始生成日报...")
    
    # 获取当前日期
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 创建目录结构
    archive_date_dir = os.path.join(ARCHIVE_DIR, current_date)
    os.makedirs(archive_date_dir, exist_ok=True)
    
    # 从数据库中获取当天的所有漏洞
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, time, source, detail_url, cve_ids FROM vulnerabilities WHERE time = ? ORDER BY time DESC", (current_date,))
    vulnerabilities = cursor.fetchall()
    conn.close()
    
    # 生成markdown内容
    markdown_content = f"# 威胁情报 {current_date}\n\n"
    markdown_content += f"共收集到 {len(vulnerabilities)} 个漏洞\n"
    markdown_content += f"最后更新时间：{current_time}\n\n"
    
    # 准备漏洞数据，用于HTML模板
    vuln_list = []
    source_distribution = {}
    
    for vuln in vulnerabilities:
        vuln_id, title, time_str, source, detail_url, cve_ids = vuln
        markdown_content += f"## [{title}]({detail_url})\n"
        markdown_content += f"- 编号：{cve_ids if cve_ids else vuln_id}\n"
        markdown_content += f"- 来源：{source}\n"
        markdown_content += f"- 时间：{time_str}\n"
        markdown_content += f"- 详情：{detail_url}\n\n"
        
        # 统计来源分布
        source_distribution[source] = source_distribution.get(source, 0) + 1
        
        # 添加到漏洞列表
        vuln_list.append({
            'title': title,
            'link': detail_url,
            'id': vuln_id,
            'cve_ids': cve_ids if cve_ids else vuln_id,
            'source': source,
            'time': time_str
        })
    
    # 计算昨日漏洞数量
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE time = ?", (yesterday,))
    yesterday_count = cursor.fetchone()[0]
    conn.close()
    
    # 生成威胁情报前瞻内容
    threat_intelligence_forecast = {
        'total_vulns': len(vulnerabilities),
        'yesterday_count': yesterday_count,
        'source_distribution': source_distribution
    }
    
    # 写入markdown文件
    markdown_file = os.path.join(archive_date_dir, f'Daily_{current_date}.md')
    is_update = os.path.exists(markdown_file)
    with open(markdown_file, 'w', encoding='utf-8') as f:
        f.write(markdown_content)
    
    if is_update:
        log_info(f"Markdown日报已更新：{markdown_file}")
    else:
        log_info(f"Markdown日报已生成：{markdown_file}")
    
    # 生成HTML内容
    try:
        # 读取HTML模板
        template_path = os.path.join(PRJ_DIR, 'static', 'template.html')
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        # 渲染HTML模板
        from jinja2 import Template
        template = Template(template_content)
        html_content = template.render(
            date=current_date,
            count=len(vulnerabilities),
            update_time=current_time,
            articles=vuln_list,
            yesterday_count=yesterday_count,
            source_distribution=source_distribution
        )
        
        # 写入HTML文件
        html_file = os.path.join(archive_date_dir, f'Daily_{current_date}.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        if is_update:
            log_info(f"HTML日报已更新：{html_file}")
        else:
            log_info(f"HTML日报已生成：{html_file}")
        
        # 更新index.html
        update_index_html()
        
    except Exception as e:
        log_error(f"生成威胁情报日报失败：{str(e)}")
        log_error(traceback.format_exc())
    
    return markdown_file, markdown_content

# 生成周报
def generate_weekly_report():
    """
    生成周报，包括Markdown和HTML格式
    周报包含本周内所有日报的链接
    """
    log_info("开始生成周报...")
    
    # 获取当前日期
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 计算本周日期范围
    today = datetime.now()
    # 计算本周一的日期
    monday = today - timedelta(days=today.weekday())
    monday_str = monday.strftime('%Y-%m-%d')
    # 计算本周日的日期
    sunday = monday + timedelta(days=6)
    sunday_str = sunday.strftime('%Y-%m-%d')
    
    # 创建目录结构
    weekly_dir_name = f'Weekly_{current_date}'
    archive_weekly_dir = os.path.join(ARCHIVE_DIR, weekly_dir_name)
    os.makedirs(archive_weekly_dir, exist_ok=True)
    
    # 获取本周内的所有日报信息
    weekly_daily_reports = []
    total_vulns = 0
    
    # 遍历本周的每一天
    for i in range(7):
        # 计算当天日期
        day_date = monday + timedelta(days=i)
        day_date_str = day_date.strftime('%Y-%m-%d')
        
        # 检查当天是否有日报
        day_dir = os.path.join(ARCHIVE_DIR, day_date_str)
        if os.path.exists(day_dir):
            # 检查当天是否有HTML日报
            html_file = os.path.join(day_dir, f'Daily_{day_date_str}.html')
            if os.path.exists(html_file):
                # 计算当天的漏洞数量
                conn = sqlite3.connect('data.db')
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE time = ?", (day_date_str,))
                day_vuln_count = cursor.fetchone()[0]
                conn.close()
                
                total_vulns += day_vuln_count
                
                # 计算相对路径
                rel_html_path = os.path.relpath(html_file, ARCHIVE_DIR)
                
                # 添加到日报列表
                weekly_daily_reports.append({
                    'date': day_date_str,
                    'vuln_count': day_vuln_count,
                    'html_path': rel_html_path
                })
    
    # 生成markdown内容
    markdown_content = f"# 威胁情报周报 {monday_str} - {sunday_str}\n\n"
    markdown_content += f"本周共收集到 {total_vulns} 个漏洞\n"
    markdown_content += f"最后更新时间：{current_time}\n\n"
    markdown_content += "## 本周威胁情报\n\n"
    
    for report in weekly_daily_reports:
        markdown_content += f"- [{report['date']}] 共 {report['vuln_count']} 个漏洞 → [{report['date']}日报](./{report['html_path']})\n"
    
    # 写入markdown文件
    markdown_file = os.path.join(archive_weekly_dir, f'Weekly_{current_date}.md')
    is_update = os.path.exists(markdown_file)
    with open(markdown_file, 'w', encoding='utf-8') as f:
        f.write(markdown_content)
    
    if is_update:
        log_info(f"Markdown周报已更新：{markdown_file}")
    else:
        log_info(f"Markdown周报已生成：{markdown_file}")
    
    # 生成HTML内容
    try:
        # 读取HTML模板
        template_path = os.path.join(STATIC_DIR, 'template.html')
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        # 渲染HTML模板
        from jinja2 import Template
        template = Template(template_content)
        html_content = template.render(
            date=f"{monday_str} - {sunday_str}",
            count=total_vulns,
            update_time=current_time,
            articles=weekly_daily_reports
        )
        
        # 写入HTML文件
        html_file = os.path.join(archive_weekly_dir, f'Weekly_{current_date}.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        if is_update:
            log_info(f"HTML周报已更新：{html_file}")
        else:
            log_info(f"HTML周报已生成：{html_file}")
        
        # 更新index.html
        update_index_html()
        
    except Exception as e:
        log_error(f"生成HTML周报失败：{str(e)}")
        log_error(traceback.format_exc())
    
    return markdown_file, markdown_content

# 更新index.html
def update_index_html():
    """
    更新index.html文件，显示所有日报列表
    """
    log_info("开始更新index.html...")
    
    # 创建index.html模板
    index_template = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>威胁情报</title>
    <style>
        /* 全局样式重置 */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        /* 现代化配色方案 */
        :root {
            --primary-color: #4285f4;
            --secondary-color: #34a853;
            --accent-color: #fbbc05;
            --danger-color: #ea4335;
            --text-primary: #202124;
            --text-secondary: #5f6368;
            --text-muted: #9aa0a6;
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-tertiary: #f1f3f4;
            --border-color: #e0e0e0;
            --shadow-sm: 0 1px 2px 0 rgba(60, 64, 67, 0.3);
            --shadow-md: 0 1px 3px 0 rgba(60, 64, 67, 0.3), 0 4px 8px 3px rgba(60, 64, 67, 0.15);
            --border-radius: 8px;
            --transition: all 0.2s ease-in-out;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: var(--bg-secondary);
            font-size: 16px;
        }
        
        /* 标题样式 */
        header {
            background: linear-gradient(135deg, var(--primary-color), #3367d6);
            color: white;
            padding: 30px;
            border-radius: var(--border-radius);
            text-align: center;
            margin-bottom: 30px;
            box-shadow: var(--shadow-md);
        }
        
        h1 {
            margin: 0 0 10px 0;
            font-size: 2.2rem;
            font-weight: 700;
        }
        
        h2 {
            font-size: 1.5rem;
            margin-top: 30px;
            margin-bottom: 15px;
            color: var(--primary-color);
            font-weight: 600;
            padding-bottom: 8px;
            border-bottom: 2px solid var(--bg-tertiary);
        }
        
        /* 报告列表 */
        .report-list {
            list-style: none;
            padding: 0;
        }
        
        .report-item {
            background-color: var(--bg-primary);
            padding: 20px;
            margin-bottom: 15px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-sm);
            transition: var(--transition);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .report-item:hover {
            box-shadow: var(--shadow-md);
            transform: translateY(-2px);
        }
        
        .report-link {
            color: var(--primary-color);
            text-decoration: none;
            font-size: 1.2rem;
            font-weight: 600;
            transition: var(--transition);
            flex: 1;
            min-width: 200px;
        }
        
        .report-link:hover {
            text-decoration: underline;
            color: #3367d6;
        }
        
        .report-info {
            color: var(--text-secondary);
            font-size: 0.95rem;
            display: flex;
            align-items: center;
            gap: 15px;
            flex-shrink: 0;
        }
        
        .report-count {
            font-weight: 600;
            color: var(--primary-color);
        }
        
        /* 统计信息 */
        .stats {
            background-color: var(--bg-primary);
            padding: 20px;
            margin-bottom: 30px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-sm);
        }
        
        .stat-item {
            display: inline-block;
            margin-right: 30px;
            margin-bottom: 10px;
        }
        
        .stat-label {
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-right: 8px;
        }
        
        .stat-value {
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--primary-color);
        }
        
        /* 响应式设计 */
        @media (max-width: 768px) {
            body {
                padding: 15px;
            }
            
            header {
                padding: 20px;
            }
            
            h1 {
                font-size: 1.8rem;
            }
            
            .report-item {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .report-link {
                width: 100%;
            }
        }
        
        /* 页脚样式 */
        footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: var(--text-muted);
            font-size: 0.9rem;
            border-top: 1px solid var(--border-color);
        }
        
        /* 空状态 */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-muted);
        }
        
        .empty-state h3 {
            color: var(--text-secondary);
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <header>
        <h1>🔒 威胁情报</h1>
        <div style="font-size: 1.1rem; opacity: 0.9;">威胁情报汇总</div>
    </header>
    
    <main>
        <h2>📊 统计信息</h2>
        <div class="stats">
            <div class="stat-item">
                <span class="stat-label">周报数：</span>
                <span class="stat-value">{{ weekly_reports|length }}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">日报数：</span>
                <span class="stat-value">{{ daily_reports|length }}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">总报告数：</span>
                <span class="stat-value">{{ weekly_reports|length + daily_reports|length }}</span>
            </div>
        </div>
        
        <h2>📋 每周威胁情报</h2>
        {% if weekly_reports %}
            <ul class="report-list">
                {% for report in weekly_reports %}
                <li class="report-item">
                    <a href="{{ report.path }}" class="report-link" target="_blank">{{ report.date }}</a>
                    <div class="report-info">
                        <span>📈 <strong class="report-count">{{ report.count }}</strong> 个漏洞</span>
                        <a href="{{ report.path }}" style="color: var(--primary-color); text-decoration: none; font-size: 0.85rem;" target="_blank">查看详情</a>
                    </div>
                </li>
                {% endfor %}
            </ul>
        {% else %}
            <div class="empty-state">
                <h3>暂无每周威胁情报</h3>
                <p>还没有生成任何每周威胁情报，请稍后再查看。</p>
            </div>
        {% endif %}
        
        <h2>📋 每日威胁情报</h2>
        {% if daily_reports %}
            <ul class="report-list">
                {% for report in daily_reports %}
                <li class="report-item">
                    <a href="{{ report.path }}" class="report-link" target="_blank">{{ report.date }}</a>
                    <div class="report-info">
                        <span>📈 <strong class="report-count">{{ report.count }}</strong> 个漏洞</span>
                        <a href="{{ report.path }}" style="color: var(--primary-color); text-decoration: none; font-size: 0.85rem;" target="_blank">查看详情</a>
                    </div>
                </li>
                {% endfor %}
            </ul>
        {% else %}
            <div class="empty-state">
                <h3>暂无每日威胁情报</h3>
                <p>还没有生成任何每日威胁情报，请稍后再查看。</p>
            </div>
        {% endif %}
    </main>
    
    <footer>
        <p>Power By 东方隐侠安全团队·Anonymous@ <a href="https://www.dfyxsec.com/" target="_blank" style="color: var(--primary-color); text-decoration: none;">隐侠安全客栈</a></p>
    </footer>
</body>
</html>
    '''
    
    # 获取所有已生成的报告，区分周报和日报
    weekly_reports = []
    daily_reports = []
    
    # 遍历archive目录下的所有目录
    if os.path.exists(ARCHIVE_DIR):
        for report_dir in sorted(os.listdir(ARCHIVE_DIR), reverse=True):
            report_path = os.path.join(ARCHIVE_DIR, report_dir)
            if os.path.isdir(report_path):
                if report_dir.startswith('Weekly_'):
                    # 处理周报
                    # 从目录名中提取日期
                    weekly_date = report_dir.replace('Weekly_', '')
                    html_file = os.path.join(report_path, f'Weekly_{weekly_date}.html')
                    if os.path.exists(html_file):
                        # 尝试获取漏洞数量
                        count = 0
                        md_file = os.path.join(report_path, f'Weekly_{weekly_date}.md')
                        if os.path.exists(md_file):
                            with open(md_file, 'r', encoding='utf-8') as f:
                                content = f.read()
                                # 从markdown文件中提取漏洞数量
                                import re
                                match = re.search(r'本周共收集到 (\d+) 个漏洞', content)
                                if match:
                                    count = match.group(1)
                        
                        # 计算相对于static目录的路径，使用正斜杠
                        rel_path = os.path.relpath(html_file, os.path.join(PRJ_DIR, 'static'))
                        # 将Windows反斜杠转换为正斜杠
                        rel_path = rel_path.replace('\\', '/')
                        # 如果路径以'../'开头，移除它以确保链接正确
                        if rel_path.startswith('../'):
                            rel_path = rel_path[3:]
                        weekly_reports.append({
                            'date': weekly_date,
                            'path': rel_path,
                            'count': count
                        })
                else:
                    # 处理日报
                    # 检查该日期目录下是否存在HTML文件
                    html_file = os.path.join(report_path, f'Daily_{report_dir}.html')
                    if os.path.exists(html_file):
                        # 尝试获取漏洞数量
                        count = 0
                        md_file = os.path.join(report_path, f'Daily_{report_dir}.md')
                        if os.path.exists(md_file):
                            with open(md_file, 'r', encoding='utf-8') as f:
                                content = f.read()
                                # 从markdown文件中提取漏洞数量
                                import re
                                match = re.search(r'共收集到 (\d+) 个漏洞', content)
                                if match:
                                    count = match.group(1)
                        
                        # 计算相对于static目录的路径，使用正斜杠
                    rel_path = os.path.relpath(html_file, os.path.join(PRJ_DIR, 'static'))
                    # 将Windows反斜杠转换为正斜杠
                    rel_path = rel_path.replace('\\', '/')
                    # 如果路径以'../'开头，移除它以确保链接正确
                    if rel_path.startswith('../'):
                        rel_path = rel_path[3:]
                        daily_reports.append({
                            'date': report_dir,
                            'path': rel_path,
                            'count': count
                        })
    
    # 渲染index.html
    from jinja2 import Template
    template = Template(index_template)
    html_content = template.render(weekly_reports=weekly_reports, daily_reports=daily_reports)
    
    # 创建static目录
    static_dir = os.path.join(PRJ_DIR, 'static')
    os.makedirs(static_dir, exist_ok=True)
    
    # 写入index.html文件到根目录
    index_file = os.path.join(PRJ_DIR, 'index.html')
    with open(index_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    log_info(f"index.html已更新到根目录：{index_file}")

# 生成WordPress RSS Feed
def generate_wordpress_rss(is_weekly=False):
    """
    生成WordPress兼容的RSS Feed
    :param is_weekly: 是否为周报模式，True表示生成包含所有漏洞的RSS，False表示只生成当天的
    """
    log_info("开始生成WordPress RSS Feed...")
    
    # 获取当前日期
    current_date = datetime.now().strftime('%Y-%m-%d')
    
    # 从数据库中获取漏洞数据
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    
    if is_weekly:
        # 生成周报时，获取所有漏洞数据
        cursor.execute("SELECT id, title, time, source, detail_url, cve_ids FROM vulnerabilities ORDER BY time DESC")
        vulnerabilities = cursor.fetchall()
    else:
        # 生成日报时，只获取当天的漏洞数据
        cursor.execute("SELECT id, title, time, source, detail_url, cve_ids FROM vulnerabilities WHERE time = ? ORDER BY time DESC", (current_date,))
        vulnerabilities = cursor.fetchall()
    conn.close()
    
    # 生成RSS内容
    rss_content = '''<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
    <channel>
        <title>威胁情报</title>
        <link>https://github.com/adminlove520/CVE_pusher</link>
        <description>威胁情报汇总 - 包含每日和每周威胁情报</description>
        <language>zh-CN</language>
        <lastBuildDate>{}</lastBuildDate>
'''.format(datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT'))
    
    for vuln in vulnerabilities:
        vuln_id, title, time_str, source, detail_url, cve_ids = vuln
        pub_date = datetime.strptime(time_str, '%Y-%m-%d').strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        # 使用f-string生成RSS item内容，避免占位符问题
        rss_content += f'''
        <item>
            <title>{title}</title>
            <link>{detail_url}</link>
            <pubDate>{pub_date}</pubDate>
            <guid isPermaLink="false">{vuln_id}</guid>
            <description><![CDATA[
                <h2>{title}</h2>
                <p><strong>编号：</strong>{cve_ids if cve_ids else vuln_id}</p>
                <p><strong>来源：</strong>{source}</p>
                <p><strong>时间：</strong>{time_str}</p>
                <p><strong>详情：</strong><a href="{detail_url}" target="_blank">{detail_url}</a></p>
            ]]></description>
            <content:encoded><![CDATA[
                <h2>{title}</h2>
                <p><strong>编号：</strong>{cve_ids if cve_ids else vuln_id}</p>
                <p><strong>来源：</strong>{source}</p>
                <p><strong>时间：</strong>{time_str}</p>
                <p><strong>详情：</strong><a href="{detail_url}" target="_blank">{detail_url}</a></p>
            ]]></content:encoded>
        </item>
'''
    
    rss_content += '''
    </channel>
</rss>
'''
    
    # 写入RSS文件
    rss_file = os.path.join(RSS_DIR, 'cve_rss.xml')
    with open(rss_file, 'w', encoding='utf-8') as f:
        f.write(rss_content)
    
    log_info(f"WordPress RSS Feed已生成：{rss_file}")
    return rss_file

# 主函数
if __name__ == '__main__':
    import argparse
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='CVE威胁情报监控')
    parser.add_argument('--once', action='store_true', help='只执行一次，适合GitHub Action运行')
    parser.add_argument('--daily-report', action='store_true', help='生成日报模式，只生成日报不推送')
    parser.add_argument('--weekly-report', action='store_true', help='生成周报模式，生成周报并推送')
    parser.add_argument('--no-push', action='store_true', help='关闭推送功能，只收集数据')
    args = parser.parse_args()
    
    try:
        # 创建数据库表
        create_database()
        log_info("=== 漏洞监控程序启动 ===")
        
        # 加载运行配置
        run_config = load_run_config()
        log_info(f"加载运行配置: {run_config}")
        
        # 记录上次运行的日期，用于检测日期变化
        last_run_date = datetime.now().strftime('%Y-%m-%d')
        log_info(f"开始运行，当前日期: {last_run_date}")
        
        # 初始化爬虫对象
        oscs1024 = OSCS1024Crawler()
        antiycloud = AntiYCloud()
        tenable = Tenable()
        ms_crawler = MicrosoftSecurityCrawler()
        okcve_crawler = OKCVECrawler()
        qianxin_crawler = QianxinCrawler()
        threatbook_crawler = ThreatBookCrawler()
        
        # 记录程序启动时间，用于控制最大运行时长
        program_start_time = time.time()
        log_info(f"程序启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 主循环
        while True:
            # 检查是否超过最大运行时间
            current_time = time.time()
            elapsed_time = current_time - program_start_time
            if elapsed_time > run_config['max_run_time']:
                log_info(f"程序运行时间已超过最大限制 {run_config['max_run_time']} 秒，自动退出")
                break
            
            try:
                # 检查是否是夜间时间，如果是则休眠
                if is_night_time(run_config):
                    current_hour = datetime.now().hour
                    log_info(f"当前时间 {current_hour} 点，处于夜间休眠时段，程序休眠")
                    # 休眠1小时后再次检查
                    time.sleep(3600)
                    continue
                
                # 检查日期是否变化
                current_date = datetime.now().strftime('%Y-%m-%d')
                if current_date != last_run_date:
                    log_info(f"检测到日期变化: {last_run_date} -> {current_date}")
                    last_run_date = current_date
                
                log_info(f"开始新一轮漏洞获取...当前日期: {current_date}")
                all_cves = []
                
                # 加载数据源配置
                datasource_config = load_datasource_config()
                log_info(f"数据源配置: {datasource_config}")
                
                # 获取各个平台的漏洞信息（每个平台的get方法已经确保只返回数据库中不存在的新漏洞）
                # OSCS1024
                if datasource_config.get('oscs1024', 1):
                    try:
                        oscs1024_vulnerabilities = oscs1024.vulnerabilities()
                        if oscs1024_vulnerabilities:
                            all_cves.extend(oscs1024_vulnerabilities)
                            log_info(f"从OSCS1024获取到 {len(oscs1024_vulnerabilities)} 条新漏洞")
                    except Exception as e:
                        log_error(f"从OSCS1024获取漏洞失败: {e}")
                else:
                    log_info("OSCS1024数据源已禁用，跳过")
                
                # 在请求之间添加短暂休眠，防止请求过于频繁
                time.sleep(2)
                
                # 安天
                if datasource_config.get('antiycloud', 1):
                    try:
                        antiycloud_cves = antiycloud.cves()
                        if antiycloud_cves:
                            all_cves.extend(antiycloud_cves)
                            log_info(f"从安天获取到 {len(antiycloud_cves)} 条新漏洞")
                    except Exception as e:
                        log_error(f"从安天获取漏洞失败: {e}")
                else:
                    log_info("安天数据源已禁用，跳过")
                
                time.sleep(2)
                
                # Tenable
                if datasource_config.get('tenable', 1):
                    try:
                        tenable_cves = tenable.cves()
                        if tenable_cves:
                            all_cves.extend(tenable_cves)
                            log_info(f"从Tenable获取到 {len(tenable_cves)} 条新漏洞")
                    except Exception as e:
                        log_error(f"从Tenable获取漏洞失败: {e}")
                else:
                    log_info("Tenable数据源已禁用，跳过")
                
                time.sleep(2)
                
                # 微软安全响应中心
                if datasource_config.get('microsoft', 1):
                    try:
                        ms_cves = ms_crawler.get_cves()
                        if ms_cves:
                            all_cves.extend(ms_cves)
                            log_info(f"从微软安全响应中心获取到 {len(ms_cves)} 条新漏洞")
                    except Exception as e:
                        log_error(f"从微软安全响应中心获取漏洞失败: {e}")
                else:
                    log_info("微软安全响应中心数据源已禁用，跳过")
                
                time.sleep(2)
                
                # CVE漏洞库
                if datasource_config.get('okcve', 1):
                    try:
                        okcve_cves = okcve_crawler.get_cves()
                        if okcve_cves:
                            all_cves.extend(okcve_cves)
                            log_info(f"从CVE漏洞库获取到 {len(okcve_cves)} 条新漏洞")
                    except Exception as e:
                        log_error(f"从CVE漏洞库获取漏洞失败: {e}")
                else:
                    log_info("CVE漏洞库数据源已禁用，跳过")
                
                # 在请求之间添加短暂休眠，防止请求过于频繁
                time.sleep(2)
                
                # 奇安信CERT
                if datasource_config.get('qianxin', 1):
                    try:
                        qianxin_cves = qianxin_crawler.get_cves()
                        if qianxin_cves:
                            all_cves.extend(qianxin_cves)
                            log_info(f"从奇安信CERT获取到 {len(qianxin_cves)} 条新漏洞")
                    except Exception as e:
                        log_error(f"从奇安信CERT获取漏洞失败: {e}")
                else:
                    log_info("奇安信CERT数据源已禁用，跳过")
                
                # 在请求之间添加短暂休眠，防止请求过于频繁
                time.sleep(2)
                
                # 微步
                if datasource_config.get('threatbook', 1):
                    try:
                        threatbook_cves = threatbook_crawler.get_cves()
                        if threatbook_cves:
                            all_cves.extend(threatbook_cves)
                            log_info(f"从微步获取到 {len(threatbook_cves)} 条新漏洞")
                    except Exception as e:
                        log_error(f"从微步获取漏洞失败: {e}")
                else:
                    log_info("微步数据源已禁用，跳过")
                
                log_info(f"本次总共获取到 {len(all_cves)} 条新漏洞信息")
                
                # 将漏洞信息插入数据库（这些都是已经过滤过的新漏洞，所以不用再次检查数据库）
                if all_cves:
                    if args.no_push or args.daily_report:
                        # 关闭推送功能，只插入数据库
                        log_info("推送功能已关闭，只将漏洞信息插入数据库")
                        conn = sqlite3.connect('data.db')
                        cur = conn.cursor()
                        insert_count = 0
                        error_count = 0
                        
                        for cve in all_cves:
                            try:
                                # 确保id不为空且有效
                                if hasattr(cve, 'id') and cve.id and cve.id.strip() != '':
                                    id = cve.id
                                    title = cve.title if hasattr(cve, 'title') and cve.title else '无标题'
                                    time_str = cve.time if hasattr(cve, 'time') and cve.time else datetime.now().strftime('%Y-%m-%d')
                                    source = cve.src if hasattr(cve, 'src') and cve.src else '未知来源'
                                    detail_url = getattr(cve, 'detail_url', '')
                                    cve_ids = cve.cve if hasattr(cve, 'cve') and cve.cve else ''
                                    
                                    # 插入数据库
                                    cur.execute("INSERT INTO vulnerabilities (id, title, time, source, detail_url, cve_ids) VALUES (?, ?, ?, ?, ?, ?)",
                                               (id, title, time_str, source, detail_url, cve_ids))
                                    conn.commit()
                                    insert_count += 1
                                    log_info(f"插入新漏洞成功：{title}")
                            except sqlite3.IntegrityError as e:
                                log_warn(f"插入数据时唯一性约束错误：{getattr(cve, 'title', '无标题')}，错误：{e}")
                                error_count += 1
                            except Exception as e:
                                log_error(f"插入数据失败：{e}")
                                log_error(traceback.format_exc())
                                error_count += 1
                        
                        conn.close()
                        log_info(f"成功插入 {insert_count} 条漏洞记录，失败 {error_count} 条")
                    else:
                        # 正常推送
                        insert_into_sqlite3_without_check(all_cves)
                else:
                    log_info("本次未获取到任何新漏洞信息")
                
                # 日报模式或单次执行模式下生成日报
                if args.daily_report or (args.once and os.environ.get('DAILY_REPORT_SWITCH', 'ON') == 'ON'):
                    # 生成日报
                    markdown_file, markdown_content = generate_daily_report()
                    # 生成WordPress RSS Feed
                    generate_wordpress_rss()
                    
                    # 不再推送日报，仅存储
                    log_info("日报已生成并存储，跳过推送")
                
                # 周报模式
                if args.weekly_report:
                    # 生成周报
                    markdown_file, markdown_content = generate_weekly_report()
                    # 生成WordPress RSS Feed（周报模式）
                    generate_wordpress_rss(is_weekly=True)
                    
                    # 推送周报到Discard（如果配置了）
                    try:
                        config = load_config()
                        if config and config[0] == "discard":
                            app_name, webhook, send_normal_msg, send_daily_report = config
                            # 确保send_daily_report是字符串类型
                            if str(send_daily_report).upper() == 'ON':
                                # 构造周报推送内容
                                current_date = datetime.now().strftime('%Y-%m-%d')
                                text = f"本周漏洞情报 {current_date}"
                                
                                # 获取本周漏洞总数
                                conn = sqlite3.connect('data.db')
                                cursor = conn.cursor()
                                # 计算本周一和周日的日期
                                today = datetime.now()
                                # 计算本周一的日期
                                monday = today - timedelta(days=today.weekday())
                                monday_str = monday.strftime('%Y-%m-%d')
                                # 计算本周日的日期
                                sunday = monday + timedelta(days=6)
                                sunday_str = sunday.strftime('%Y-%m-%d')
                                # 查询本周内的所有漏洞数量
                                cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE time >= ? AND time <= ?", (monday_str, sunday_str))
                                vuln_count = cursor.fetchone()[0]
                                conn.close()
                                
                                msg = f"本周共收集到 {vuln_count} 个漏洞"
                                html_file = os.path.relpath(os.path.join(ARCHIVE_DIR, f'Weekly_{current_date}', f'Weekly_{current_date}.html'), PRJ_DIR)
                                
                                # 推送周报到Discard
                                discard(text, msg, webhook, is_daily_report=True, html_file=html_file, markdown_content=markdown_content)
                                log_info("Discard周报推送成功")
                            else:
                                log_info("Discard周报推送已禁用，跳过推送")
                    except Exception as e:
                        log_error(f"推送Discard周报失败：{e}")
                        log_error(traceback.format_exc())
                
                log_info("本轮漏洞获取完成，等待下一轮...")
                
                # 如果是单次执行、日报模式或周报模式，直接退出
                if args.once or args.daily_report or args.weekly_report:
                    log_info("单次执行、日报模式或周报模式完成，退出程序")
                    break
                
                # 按照配置的检查间隔休眠
                log_info(f"按照配置休眠 {run_config['check_interval']} 秒")
                time.sleep(run_config['check_interval'])
                
            except Exception as e:
                log_error(f"主循环发生异常: {e}")
                log_error(traceback.format_exc())
                # 发生错误时按照配置的重试间隔等待后重试
                log_info(f"发生异常，按照配置休眠 {run_config['exception_retry_interval']} 秒后重试")
                time.sleep(run_config['exception_retry_interval'])
                
    except Exception as e:
        log_error(f"程序启动失败: {e}")
        log_error(traceback.format_exc())

# 生成日报
def generate_daily_report():
    """
    生成日报，包括Markdown和HTML格式
    """
    log_info("开始生成日报...")
    
    # 获取当前日期
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 创建目录结构
    archive_date_dir = os.path.join(ARCHIVE_DIR, current_date)
    os.makedirs(archive_date_dir, exist_ok=True)
    
    # 从数据库中获取当天的所有漏洞
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, time, source, detail_url, cve_ids FROM vulnerabilities WHERE time = ? ORDER BY time DESC", (current_date,))
    vulnerabilities = cursor.fetchall()
    conn.close()
    
    # 生成markdown内容
    markdown_content = f"# 威胁情报 {current_date}\n\n"
    markdown_content += f"共收集到 {len(vulnerabilities)} 个漏洞\n"
    markdown_content += f"最后更新时间：{current_time}\n\n"
    
    # 准备漏洞数据，用于HTML模板
    vuln_list = []
    for vuln in vulnerabilities:
        vuln_id, title, time_str, source, detail_url, cve_ids = vuln
        markdown_content += f"## [{title}]({detail_url})\n"
        markdown_content += f"- 编号：{cve_ids if cve_ids else vuln_id}\n"
        markdown_content += f"- 来源：{source}\n"
        markdown_content += f"- 时间：{time_str}\n"
        markdown_content += f"- 详情：{detail_url}\n\n"
        
        # 添加到漏洞列表
        vuln_list.append({
            'title': title,
            'link': detail_url,
            'id': vuln_id,
            'cve_ids': cve_ids if cve_ids else vuln_id,
            'source': source,
            'time': time_str
        })
    
    # 写入markdown文件
    markdown_file = os.path.join(archive_date_dir, f'Daily_{current_date}.md')
    is_update = os.path.exists(markdown_file)
    with open(markdown_file, 'w', encoding='utf-8') as f:
        f.write(markdown_content)
    
    if is_update:
        log_info(f"Markdown日报已更新：{markdown_file}")
    else:
        log_info(f"Markdown日报已生成：{markdown_file}")
    
    # 生成HTML内容
    try:
        # 读取HTML模板
        template_path = os.path.join(STATIC_DIR, 'template.html')
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        # 渲染HTML模板
        from jinja2 import Template
        template = Template(template_content)
        html_content = template.render(
            date=current_date,
            count=len(vulnerabilities),
            update_time=current_time,
            articles=vuln_list
        )
        
        # 写入HTML文件
        html_file = os.path.join(archive_date_dir, f'Daily_{current_date}.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        if is_update:
            log_info(f"HTML日报已更新：{html_file}")
        else:
            log_info(f"HTML日报已生成：{html_file}")
        
        # 更新index.html
        update_index_html()
        
    except Exception as e:
        log_error(f"生成HTML日报失败：{str(e)}")
        log_error(traceback.format_exc())
    
    return markdown_file, markdown_content

# 更新index.html

    """
    生成WordPress兼容的RSS Feed
    """
    log_info("开始生成WordPress RSS Feed...")
    
    # 获取当前日期
    current_date = datetime.now().strftime('%Y-%m-%d')
    
    # 从数据库中获取当天的所有漏洞
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, time, source, detail_url, cve_ids FROM vulnerabilities WHERE time = ? ORDER BY time DESC", (current_date,))
    vulnerabilities = cursor.fetchall()
    conn.close()
    
    # 生成RSS内容
    rss_content = '''<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
    <channel>
        <title>威胁情报</title>
        <link>https://github.com/adminlove520/CVE_pusher</link>
        <description>每日威胁情报汇总</description>
        <language>zh-CN</language>
        <lastBuildDate>{}</lastBuildDate>
'''.format(datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT'))
    
    for vuln in vulnerabilities:
        vuln_id, title, time_str, source, detail_url, cve_ids = vuln
        pub_date = datetime.strptime(time_str, '%Y-%m-%d').strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        # 使用f-string生成RSS item内容，避免占位符问题
        rss_content += f'''
        <item>
            <title>{title}</title>
            <link>{detail_url}</link>
            <pubDate>{pub_date}</pubDate>
            <guid isPermaLink="false">{vuln_id}</guid>
            <description><![CDATA[
                <h2>{title}</h2>
                <p><strong>编号：</strong>{cve_ids if cve_ids else vuln_id}</p>
                <p><strong>来源：</strong>{source}</p>
                <p><strong>时间：</strong>{time_str}</p>
                <p><strong>详情：</strong><a href="{detail_url}" target="_blank">{detail_url}</a></p>
            ]]></description>
            <content:encoded><![CDATA[
                <h2>{title}</h2>
                <p><strong>编号：</strong>{cve_ids if cve_ids else vuln_id}</p>
                <p><strong>来源：</strong>{source}</p>
                <p><strong>时间：</strong>{time_str}</p>
                <p><strong>详情：</strong><a href="{detail_url}" target="_blank">{detail_url}</a></p>
            ]]></content:encoded>
        </item>
'''
    
    rss_content += '''
    </channel>
</rss>
'''
    
    # 写入RSS文件
    rss_file = os.path.join(RSS_DIR, 'cve_rss.xml')
    with open(rss_file, 'w', encoding='utf-8') as f:
        f.write(rss_content)
    
    log_info(f"WordPress RSS Feed已生成：{rss_file}")
    return rss_file