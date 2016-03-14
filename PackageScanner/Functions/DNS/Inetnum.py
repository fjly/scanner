from ipwhois import IPWhois
from pprint import pprint
from PackageScanner.Scanner import Scanner_v1
from PackageScanner.OutputFormatter import OutputFormatter
from PackageScanner.TargetLoader import TargetLoader
from PackageThread.JobQueue import Job
import urllib,urllib2,re,sys,json
from lxml import html

#is not use
class SubDomainJob(Job):
    def __init__(self,id, key):
        Job.__init__(self,id)
        self.keyword = key.strip()
    #search ripe db
    def inetRipe(self):
        ripe_url = 'https://apps.db.ripe.net/search/full-text.html'
        re_nextpage = r'resultsView:paginationView:dpaginationForm:main:after:repeat:0:byIndex'
        re_nextpage = re.compile(re_nextpage)
        #set cookies
        cookies = urllib2.HTTPCookieProcessor()
        opener = urllib2.build_opener(cookies)
        #to make sure the javax_faces_ViewState has value
        for i in range(0,3):
            ret1 = opener.open(ripe_url)
            page1 = ret1.read()
            javax_faces_ViewState = re.search(r'-?\d{19}:-?\d{19}',page1)
            if javax_faces_ViewState is not None:
                break

        data_first = 'home_search=home_search&home_search%3Asearchform_q=' + self.keyword + '&home_search%3AdoSearch=Search&javax.faces.ViewState=' + urllib.quote(javax_faces_ViewState.group())
        headers = {'host':'apps.db.ripe.net',
                'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0',
                'Content-Type':'application/x-www-form-urlencoded',
                'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }

        #first search
        request = urllib2.Request(ripe_url,headers = headers, data = data_first)
        for i in range(0,3):
            ret2 = opener.open(request)
            page2 = ret2.read()
            javax_faces_ViewState = re.search(r'-?\d{19}:-?\d{19}',page2)
            if javax_faces_ViewState is not None:
                break
        self.result['inetnum'] = []
        self.result['inetnum'].append(page2)

        #decide that has the next page and get other page
        index = 2
        while(re_nextpage.search(page2) is not None):
            print index
            data_next = 'resultsView%3ApaginationViewTop%3ApaginationForm=resultsView%3ApaginationViewTop%3ApaginationForm&resultsView%3ApaginationViewTop%3ApaginationForm%3Amain%3Aafter%3Arepeat%3A0%3AbyIndex=' + str(index) + '&javax.faces.ViewState=' + urllib.quote(javax_faces_ViewState.group())
            request = urllib2.Request(ripe_url,headers = headers, data = data_next)
            page2 = None
            for i in range(0,3):
                ret2 = opener.open(request)
                page2 = ret2.read()
                javax_faces_ViewState = re.search(r'-?\d{19}:-?\d{19}',page2)
                if javax_faces_ViewState is not None:
                    break
            self.result['inetnum'].append(page2)
            index += 1
    #search npnic db
    def inetNpnic(self):
        npnic_url = 'http://wq.apnic.net/whois-search/query?searchtext=' + urllib2.unquote(self.keyword)
        rep = urllib2.urlopen(npnic_url)
        page = rep.read()
        self.result['inetnum'] = page

    def do(self):
        self.result = {
            'keyword' : self.keyword,
            'inetnum' : None,
            'exceptions' : [],
            'exec_time':0
        }

        try:
        #    self.inetRipe()
            self.inetNpnic()
        except Exception as e:
            self.result['exceptions'].append(e)
            print e

        #result['exec_time'] = (time()-start)
        return Job.do(self)

class NpnicInetnumAttributesDictPrint():
    def __init__(self,attributes,inetnum_print_keywords):
        self.attributes = attributes
        self.inetnum_print_keywords = inetnum_print_keywords

    def printAttr(self):
        for attr in self.attributes:
            if attr['name'] in self.inetnum_print_keywords:
                print  '\r'+attr['name'] + u'  :  ' + "".join(attr['values'])

class OutputFormatterSubDomainRecord(OutputFormatter):
    def __init__(self):
        OutputFormatter.__init__(self)
        self.whois={}

    #npnic print
    def printNpnic(self,report_object):
        report_object = report_object.result['inetnum']
        inet = json.loads(report_object)
        for inetnum in inet:
            if inetnum['type'] == 'object' and inetnum['objectType'] == 'inetnum':
                inetnum_print_keywords = ('inetnum','netname')
                s = NpnicInetnumAttributesDictPrint(inetnum['attributes'],inetnum_print_keywords)
                s.printAttr()

    #ripe print
    def printRipe(self,report_object):
        report_object = report_object.result['inetnum']
        for page in report_object:
            page = page.decode('utf-8')
            page = page.replace('<b>','')
            page = page.replace('</b>','')
            page = page.replace('href="','href="https://apps.db.ripe.net/search/')
            html_content = html.fromstring(page)
            html_content = html_content.xpath("//div[@class='padding'][@id='results']")  #html_content[0] = '<div class="padding" id="results">'
            if len(html_content) == 0 :
                break
            for cl in html_content[0].getchildren():   #cl = 'margin-bottom grey-border-top padding-top results'
                for inet in cl.getchildren():
                    if inet.text  is not None:
                        print inet.text,
                    for text in inet.getchildren():
                        print '\r'+text.text
                        if text.attrib['href'] is not None:
                            print text.attrib['href']
                print "\n"

    #ip whois print
    def printIpWhois(self,report_object):
        report_object = report_object.result
        if report_object['whois'] != None and len(report_object['whois']) > 0:
            if report_object['whois']['nets'] != None and len(report_object['whois']['nets']) > 0:
                len_tmp1 = len(report_object['whois']['nets'])
                len_tmp2 = len_tmp1
                nets = report_object['whois']['nets']
                for i in range(0,len_tmp1):
                    len_tmp2 = len_tmp2 - 1
                    if nets[len_tmp2]['name'] != None and nets[len_tmp2]['range'] != None:
                        break

                print '\rip           :'+report_object['keyword']
                if nets[len_tmp2]['name'] != None:
                    print 'inetname     :'+nets[len_tmp2]['name']
                if nets[len_tmp2]['range'] != None:
                    print 'range        :'+nets[len_tmp2]['range']
            else:
                print 'ip is not get whois :'+report_object['keyword']

    #change this method
    def printResult(self, report_object):
        if report_object.result['type'] == 'ripe':
            self.printRipe(report_object)
        elif report_object.result['type'] == 'apnic':
            self.printNpnic(report_object)
        elif report_object.result['type'] == 'ip':
            self.printIpWhois(report_object)

class WhoisServer(Job):
    def __init__(self,id):
        Job.__init__(self,id)
        self.result = {
            'keyword' : None,
            'ip':None,
            'inetnum' : None,
            'exceptions' : [],
            'exec_time':0,
            'type':None,
            'whois':None
        }
        pass
    def queryIP(self,ip):
        try:
            self.result['type'] = 'ip'
            self.result['keyword'] = ip
            self.ip = ip
            ipwhois = IPWhois(self.ip)
            self.result['whois'] = ipwhois.lookup()
        except Exception as e:
            self.result['exceptions'].append(e)
        return self

class WhoisServerAPNIC(WhoisServer):
    def __init__(self,id):
        WhoisServer.__init__(self,id)
        self.npnic_url = 'http://wq.apnic.net/whois-search/query?searchtext='
        self.result['type'] = 'apnic'

    def queryKeyword(self,keyword):
        try:
            self.result['keyword'] = keyword
            npnic_url = self.npnic_url + urllib2.unquote(keyword)
            rep = urllib2.urlopen(npnic_url)
            page = rep.read()
            self.result['inetnum'] = page
        except Exception as e:
            self.result['exceptions'].append(e)
        return self

class WhoisServerRIPE(WhoisServer):
    def __init__(self,id):
        WhoisServer.__init__(self,id)
        self.ripe_url = 'https://apps.db.ripe.net/search/full-text.html'
        self.re_nextpage = re.compile(r'resultsView:paginationView:dpaginationForm:main:after:repeat:0:byIndex')
        self.result['type'] = 'ripe'

    def queryKeyword(self,keyword):
        try:
            self.result['keyword'] = keyword
            #set cookies
            cookies = urllib2.HTTPCookieProcessor()
            opener = urllib2.build_opener(cookies)
            #to make sure the javax_faces_ViewState has value
            for i in range(0,3):
                ret1 = opener.open(self.ripe_url)
                page1 = ret1.read()
                javax_faces_ViewState = re.search(r'-?\d{19}:-?\d{19}',page1)
                if javax_faces_ViewState is not None:
                    break
            data_first = 'home_search=home_search&home_search%3Asearchform_q=' + keyword + '&home_search%3AdoSearch=Search&javax.faces.ViewState=' + urllib.quote(javax_faces_ViewState.group())
            headers = {'host':'apps.db.ripe.net',
                    'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0',
                    'Content-Type':'application/x-www-form-urlencoded',
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            #the first page whith first search
            request = urllib2.Request(self.ripe_url,headers = headers, data = data_first)
            for i in range(0,3):
                ret2 = opener.open(request)
                page2 = ret2.read()
                javax_faces_ViewState = re.search(r'-?\d{19}:-?\d{19}',page2)
                if javax_faces_ViewState is not None:
                    break
            self.result['inetnum'] = []
            self.result['inetnum'].append(page2)

            #decide that has the next page and get other page
            index = 2
            while(self.re_nextpage.search(page2) is not None):
                print index
                data_next = 'resultsView%3ApaginationViewTop%3ApaginationForm=resultsView%3ApaginationViewTop%3ApaginationForm&resultsView%3ApaginationViewTop%3ApaginationForm%3Amain%3Aafter%3Arepeat%3A0%3AbyIndex=' + str(index) + '&javax.faces.ViewState=' + urllib.quote(javax_faces_ViewState.group())
                request = urllib2.Request(self.ripe_url,headers = headers, data = data_next)
                page2 = None
                for i in range(0,3):
                    ret2 = opener.open(request)
                    page2 = ret2.read()
                    javax_faces_ViewState = re.search(r'-?\d{19}:-?\d{19}',page2)
                    if javax_faces_ViewState is not None:
                        break
                self.result['inetnum'].append(page2)
                index += 1
        except Exception as e:
            self.result['exceptions'].append(e)
        return self

class WhoisJob(Job):
    def __init__(self, id, whois_server,ip=None, keyword=None):
        Job.__init__(self,id)
        self._whois_server = whois_server
        self.ip = ip
        self.keyword = keyword

    def do(self):
        if self.ip is not None:
            return self._whois_server.queryIP(self.ip)
        if self.keyword is not None:
            return self._whois_server.queryKeyword(self.keyword)

#usually change the classname to someone with the filename
#change the classname and then goto change the class WhoisJob
class WhoisScanner(Scanner_v1):
    def __init__(self):
        Scanner_v1.__init__(self)
        self._outputFormatters.append(OutputFormatterSubDomainRecord())
        self.domain_prefix_list = []
        self._description = "this is a whois query"

    def createJobs(self,targets):
        ip_re = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        ip_re = re.compile(ip_re)
        keyword = None
        ip = None
        keys = targets
        org_name = None
        for index, key in enumerate(keys):
            key = key.strip()
            if ip_re.match(key):
                ip = key
            else:
                #confirm the input file format is search keyword \t org_name
                keyword,org_name = key.split('\t')

            if ip is not None:
                job = WhoisJob(index+1, WhoisServer(index+1), ip=ip, keyword=keyword)
                ip = None
            if org_name == 'apnic':
                job = WhoisJob(index+1, WhoisServerAPNIC(index+1), ip=ip, keyword=keyword)
            if org_name == 'ripe':
                job = WhoisJob(index+1, WhoisServerRIPE(index+1), ip=ip, keyword=keyword)

            self._jobQueue.addJob(job)
        return len(self.domain_prefix_list)

if __name__ == '__main__':

    t = TargetLoader()
    keywords = t.loadTargets(file ='dns.txt')
    s = WhoisScanner()
    s.scan(keywords,thread_count=1)
    for r in s:
        pass