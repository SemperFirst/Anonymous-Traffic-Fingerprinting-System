from flowcontainer.extractor import extract
import os
import random
import pymysql
import json

class Identify():
    def __init__(self) -> None:
        self.path="D:\Public_data\LL_JAC\pcap-logs"
        self.host = '127.0.0.1'
        self.user = 'root'
        self.passwd = '123456'
        self.db = 'amtraffic'
        self.port=3306
        self.conn = pymysql.connect(host=self.host, port=self.port, user=self.user, passwd=self.passwd, db=self.db,
                                    charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
        self.cur = self.conn.cursor()
    
    def get_onefinger(self,file):
        #从单个流量文件中提取REQ和RES指纹
        result= extract(file)
        payload=[]
        req=[]
        res=[]
        for key in result:
            value = result[key]
            #获取流量包中载荷部分，载荷部分去除了流量包中握手和为空的部分TCP包
            payload=value.payload_lengths 
        for i in payload:
            if i>= 300:
                req.append(i)
            if i>=-1450 and i<=-300:
                res.append(i)
        return req,res
    
    def levern(self,list1,list2):
        #核心函数:计算两个集合的编辑距离
        d=0
        lenmax=max(len(list1),len(list2))
        lenmin=min(len(list1),len(list2))
        for i in range(lenmin):
            if list1[i]!=list2[i]:
                d+=1
        d=d+lenmax-lenmin
        if lenmax:
            return d/lenmax
        else:
            return 0
    
    def get_test_filename(self):
        #模拟随机获取一个流量文件名 文件名后缀为网站名
        path=self.path
        site_dir=[]
        test_file=[]
        test_filenames=[]
        test_dir=''
        for dir in os.listdir(path):
            site_dir.append(dir)
        randint=random.randint(0,len(site_dir))
        test_dir=site_dir[randint-1]
        file_path=os.path.join(path,test_dir)
        for root, dirs, files in os.walk(file_path):
            for file in files:
                filename=os.path.join(file_path,file)
                test_file.append(filename)
        randint=random.randint(0,2001)
        test_filename=test_file[randint]
        test_filenames.append(test_filename)
        return test_filenames
    
    def get_filename(self):
        path=r"D:\论文code\temp"
        test_filenames=[]
        for root, dirs, files in os.walk(path):
            for file in files:
                filename=os.path.join(path,file)
                test_filenames.append(filename)
        return test_filenames
    
    def main(self):
        #主函数入口
        files=self.get_filename()
        results={}
        for  i in files:
            testfinger=self.get_onefinger(i) #获取测试文件并生成文件特征 
            req=testfinger[0]
            res=testfinger[1]
            if len(req) or len(res):
                sql="SELECT * FROM `amtraffic`.`finger`"
                result={}
                self.cur.execute(sql)#将文件特征与数据库指纹比对
                rows=self.cur.fetchall()
                for row in rows:
                    reqfinger=row['reqfinger']
                    reqfinger=eval(reqfinger)
                    resfinger=row['resfinger']
                    resfinger=eval(resfinger)
                    name=row['name']
                    LC=0.6*self.levern(req,reqfinger)+0.4*self.levern(res,resfinger)
                    result[name]=LC        
                min_key = min(result, key=lambda key: result[key])#结果形成一个字典 网站名和识别系数大小 根据最大值判断网站
                if result[min_key]>0.5:
                    results[i]='网站不在监控范围或者可能识别错误'
                else:
                    results[i]=min_key
            else:
                results[i]='网站不在监控范围或者可能识别错误'
        return results
    
    def fileay(self):
        files=self.get_filename()
        results={}
        num=len(files)
        for i in range(num):
            result= extract(files[i])
            for key in result:
                value = result[key]
                src=value.src
                dst=value.dst
                sport=value.sport
                dport=value.dport
                ipsrc=str(src)+':'+str(sport)
                ipdst=str(dst)+':'+str(dport)
                payload=value.payload_lengths 
            results[i]=[i,files[i],ipsrc,ipdst,'SSH',str(payload)]
        return results

            
if __name__ == '__main__':
    print(Identify().fileay())
    """
    results=[]
    for i in range(10):
        result=Identify().main()
        results.append(result)
    ac=sum(results)/len(results)
    print(results)
    print(ac)
    """
    



        
    

