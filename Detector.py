"""
MOVERY Detector - 漏洞检测系统
作者: Seunghoon Woo (seunghoonwoo@korea.ac.kr)
修改: August 5, 2022

主要功能:
1. 扫描目标程序中的潜在漏洞
2. 支持抽象和非抽象两种匹配模式
3. 基于代码相似度的漏洞检测
4. 支持多种漏洞特征匹配方式
"""

# 导入必要的库
import os
import sys
currentPath = os.getcwd()
sys.path.append(currentPath + "/config/")
import movery_config
import subprocess
import re
import json
import time

"""全局变量"""
delimiter = "\r\0?\r?\0\r"  # 用于分隔的定界符
theta = 0.5                 # 相似度阈值

"""路径配置"""
# 漏洞特征数据集路径
vulESSLinePath   = currentPath + "/dataset/vulESSLines/"    # 漏洞必要行路径
vulDEPLinePath   = currentPath + "/dataset/vulDEPLines/"    # 漏洞依赖行路径
noOldESSLinePath = currentPath + "/dataset/noOldESSLines/"  # 无旧版本必要行路径
noOldDEPLinePath = currentPath + "/dataset/noOldDEPLines/"  # 无旧版本依赖行路径
patESSLinePath   = currentPath + "/dataset/patESSLines/"    # 补丁必要行路径
patDEPLinePath   = currentPath + "/dataset/patDEPLines/"    # 补丁依赖行路径
vulBodyPath      = currentPath + "/dataset/vulBodySet/"     # 漏洞函数体集合路径
vulHashPath      = currentPath + "/dataset/vulHashes/"      # 漏洞哈希值路径
targetPath       = currentPath + "/dataset/tarFuncs/"       # 目标函数路径
ossidxPath       = currentPath + "/dataset/oss_idx.txt"     # OSS索引文件路径
idx2verPath      = currentPath + "/dataset/idx2cve.txt"     # CVE索引文件路径

"""工具函数"""
def intersect(a, b):
    """计算两个列表的交集"""
    return list(set(a) & set(b))

def union(a, b):
    """计算两个列表的并集"""
    return list(set(a) | set(b))

def jaccard_sim(a, b):
    """计算Jaccard相似度: 交集大小/并集大小"""
    inter = len(list(set(a).intersection(b)))
    union = (len(set(a)) + len(b)) - inter
    return float(inter) / union

def normalize(string):
    """
    标准化字符串:
    - 移除回车符和制表符
    - 移除所有空格
    - 转换为小写
    参考: https://github.com/squizz617/vuddy
    """
    return ''.join(string.replace('\r', '').replace('\t', '').split(' ')).lower()

def removeComment(string):
    """
    移除C/C++风格的注释
    支持:
    - 单行注释 (//)
    - 多行注释 (/* */)
    参考: https://github.com/squizz617/vuddy
    """
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def readFile(path):
    """
    读取文件内容,支持多种编码:
    - UTF-8
    - CP949
    - euc-kr
    """
    body = ''
    try:
        fp = open(path, 'r', encoding = "UTF-8")
        body = ''.join(fp.readlines()).strip()
    except:
        try:
            fp = open(path, 'r', encoding = "CP949")
            body = ''.join(fp.readlines()).strip()
        except:
            try:
                fp = open(path, 'r', encoding = "euc-kr")
                body = ''.join(fp.readlines()).strip()
            except:
                pass
    return body

def readOSSIDX():
    """读取OSS索引文件,构建OSS索引字典"""
    ossIDX = {}
    with open(ossidxPath, 'r', encoding = "UTF-8") as foss:
        body = ''.join(foss.readlines()).strip()
        for each in body.split('\n'):
            if each.split('@@')[0] not in ossIDX:
                ossIDX[each.split('@@')[0]] = []
            ossIDX[each.split('@@')[0]].append(each.split('@@')[1])
    return ossIDX

def readIDX2VER():
    """读取CVE索引文件,构建CVE版本映射"""
    idx2ver = {}
    with open(idx2verPath, 'r', encoding = "UTF-8") as idxfp:
        body = ''.join(idxfp.readlines()).strip()
        for each in body.split('\n'):
            idx2ver[each.split('##')[0]] = (each.split('##')[1])
    return idx2ver

def readVulHashes():
    """读取漏洞哈希值文件,构建漏洞哈希字典"""
    vulHashes = {}
    for files in os.listdir(vulHashPath):
        oss = files.split('_hash.txt')[0]
        vulHashes[oss] = []

        with open(vulHashPath+ files, 'r', encoding = "UTF-8") as fo:
            body = ''.join(fo.readlines()).strip()
            for each in body.split('\n'):
                hashval = each.split('\t')[0]
                vulHashes[oss].append(hashval)
    return vulHashes

def spaceReduction(tar, vulHashes, ossIDX):
    """
    搜索空间规约函数
    
    参数:
        tar: 目标程序
        vulHashes: 漏洞哈希值字典
        ossIDX: OSS索引字典
    
    返回:
        tarIDX: 目标索引列表
        tarFuncs: 目标函数字典
    
    功能:
    1. 通过哈希匹配快速筛选可能存在漏洞的函数
    2. 减少后续详细分析的搜索空间
    """
    funcHash  = {}
    tarIDX    = []
    tarFuncs  = {}
    res       = {}

    # 检查目标文件是否存在
    if not os.path.isfile(targetPath + '/' + tar + '_hash.txt') or not os.path.isfile(targetPath + '/' + tar + '_funcs.txt'):
        print ("No tar files (tar_funcs.txt and tar_hash.txt) in './dataset/tarFuncs/'.")
        sys.exit()

    # 读取目标函数哈希值
    with open(targetPath + '/' + tar + '_hash.txt', 'r', encoding = "UTF-8") as fh:
        body = ''.join(fh.readlines()).strip()
        for each in body.split('\n'):
            hashval = each.split('\t')[0]
            hashpat = each.split('\t')[1]
            if hashval not in funcHash:
                funcHash[hashval] = []
            funcHash[hashval].append(hashpat)

    # 进行哈希匹配
    for oss in vulHashes:
        if oss in ossIDX:
            for hashval in vulHashes[oss]:
                if hashval in funcHash:    
                    tarIDX.extend(ossIDX[oss])
                    for eachPat in funcHash[hashval]:
                        res['@@'.join(eachPat.split('##')[1].split('@@')[:-1])] = 1

    tarIDX = list(set(tarIDX))

    # 读取目标函数
    with open(targetPath + tar + '_funcs.txt', 'r', encoding = "UTF-8") as ft:
        tarFuncs = json.load(ft)

    # 筛选相关函数
    tempTar = {}
    for file in tarFuncs:
        if ('@@'.join(file.split('##')[1].split('@@')[:-1])) in res:
            tempTar[file] = tarFuncs[file]
    
    tarFuncs = tempTar
    return tarIDX, tarFuncs

def detector(tar):
    """
    主要漏洞检测函数
    
    参数:
        tar: 目标程序名称
    
    功能:
    1. 加载必要的索引和哈希数据
    2. 进行空间规约
    3. 对每个潜在漏洞进行检测:
       - 检查必要代码行
       - 检查依赖关系
       - 计算相似度
       - 应用抽象或非抽象匹配
    """
    print ()
    print ("[+] NOW MOVERY SCANS " + tar + "...")
    print ()

    # 计时开始
    mtime  = 0.0     

    # 读取必要数据
    ossIDX           = readOSSIDX()
    idx2ver          = readIDX2VER()
    vulHashes        = readVulHashes()
    tarIDX, tarFuncs = spaceReduction(tar, vulHashes, ossIDX)

    # 对每个漏洞文件进行检测
    for vulFiles in os.listdir(vulBodyPath):
        temp = {}
        idx = vulFiles.split('_')[0]

        # 仅考虑目标程序中重用的OSS
        if idx not in tarIDX:
            continue

        vulBody = ""

        # 初始化各类特征行
        vul_essLines = []  # 漏洞必要行
        vul_depLines = {}  # 漏洞依赖行
        pat_essLines = []  # 补丁必要行
        pat_depLines = {}  # 补丁依赖行

        flag = 0   # 标记漏洞类型
        isAbs = 1  # 是否使用抽象匹配

        # 读取漏洞信息
        with open(vulBodyPath + vulFiles, 'r', encoding = "UTF-8") as f:
            vulBody = json.load(f)
        
        # 处理不同类型的漏洞特征
        if idx + "_common.txt" in os.listdir(vulESSLinePath):
            # 存在最老的漏洞函数且补丁删除了部分代码
            with open(vulESSLinePath + idx + "_common.txt", 'r', encoding = "UTF-8") as f:
                vul_essLines = json.load(f)
            with open(vulDEPLinePath + idx + "_depen.txt", 'r', encoding = "UTF-8") as fd:
                vul_depLines = json.load(fd)
            flag = 1

        elif idx + "_minus.txt" in os.listdir(noOldESSLinePath):
            # 不存在最老的漏洞函数且补丁删除了部分代码
            with open(noOldESSLinePath + idx + "_minus.txt", 'r', encoding = "UTF-8") as f:
                vul_essLines = json.load(f)
            with open(noOldDEPLinePath + idx + "_depen.txt", 'r', encoding = "UTF-8") as fd:
                vul_depLines = json.load(fd)
            flag = 1

        if idx + "_plus.txt" in os.listdir(patESSLinePath):
            # 补丁特征
            with open(patESSLinePath + idx + "_plus.txt", 'r', encoding = "UTF-8") as f:
                pat_essLines = json.load(f)
            with open(patDEPLinePath + idx + "_depen.txt", 'r', encoding = "UTF-8") as fd:
                pat_depLines = json.load(fd)
            flag = 2
        else:
            if len(vul_essLines) == 0:
                continue

        # 漏洞类型标记:
        # del o add x  1 - 只有删除
        # del o add o  2 - 既有删除也有添加
        # del x add o  3 - 只有添加

        # 选择性抽象处理
        if len(pat_essLines) > 0:
            patLines      = []  # 补丁行
            patAbsLines   = []  # 抽象补丁行
            vulLines      = []  # 漏洞行
            vulAbsLines   = []  # 抽象漏洞行
            tempNewPat    = []  # 临时新补丁
            tempNewAbsPat = []  # 临时新抽象补丁

            # 处理补丁行
            for eachPat in pat_essLines:
                patLines.append(normalize(eachPat['pat_body']))
                patAbsLines.append(normalize(eachPat['abs_body']))

                if normalize(eachPat['pat_body']) not in vulBody['vul_body']:
                    tempNewPat.append(normalize(eachPat['pat_body']))
                    tempNewAbsPat.append(normalize(eachPat['abs_body']))
            
            # 清理特殊字符
            temp = []
            temp[:] = (value for value in tempNewPat if value != '{' and value != '}' and value != '')
            newPat = set(temp)

            temp[:] = (value for value in tempNewAbsPat if value != '{' and value != '}' and value != '')
            newAbsPat = set(temp)

            # 处理漏洞行
            if len(vul_essLines) > 0:
                for eachVul in vul_essLines:
                    vulLines.append(normalize(eachVul['vul_body']))
                    vulAbsLines.append(normalize(eachVul['abs_body']))
                if (set(patAbsLines) != set(vulAbsLines)):  # 应用抽象
                    isAbs = 1
                else:
                    isAbs = 0
            else:
                flag = 3

        # 处理依赖行
        if len(vul_depLines) > 0:
            if "vul" in vul_depLines:
                vulDepens = vul_depLines["vul"]
            else:
                vulDepens = vul_depLines

            # 初始化依赖行集合
            absDepens_withoutOLD = []  # 无旧版本抽象依赖
            norDepens_withoutOLD = []  # 无旧版本标准依赖
            absDepens_withOLD    = []  # 有旧版本抽象依赖
            norDepens_withOLD    = []  # 有旧版本标准依赖

            # 处理依赖行
            for eachDepen in vulDepens:
                if len(vulDepens[eachDepen]) > 0:
                    for each in vulDepens[eachDepen]:
                        absDepens_withoutOLD.append(removeComment(each["abs_norm_vul"]))
                        norDepens_withoutOLD.append(removeComment(each["orig_norm_vul"]))

            # 处理旧版本依赖
            if "old" in vul_depLines:
                vulDepens = vul_depLines["old"]
                for eachDepen in vulDepens:
                    if len(vulDepens[eachDepen]) > 0:
                        for each in vulDepens[eachDepen]:
                            absDepens_withOLD.append(removeComment(each["abs_norm_vul"]))
                            norDepens_withOLD.append(removeComment(each["orig_norm_vul"]))

            # 转换为集合
            absDepens_withoutOLD = set(absDepens_withoutOLD)
            absDepens_withOLD = set(absDepens_withOLD)
            norDepens_withoutOLD = set(norDepens_withoutOLD)
            norDepens_withOLD = set(norDepens_withOLD)

        # 提取核心漏洞行
        coreAbsVulLines = []
        coreVulLines = []

        for val in vul_essLines:
            coreAbsVulLines.append(normalize(val["abs_body"]))
            coreVulLines.append(normalize(val["vul_body"]))

        coreAbsVulLines = set(coreAbsVulLines)
        coreVulLines    = set(coreVulLines)

        # 提取函数体集合
        vulBodySet = []
        oldBodySet = []

        vulBodySet = set(vulBody['vul_body'])
        if 'old_body' in vulBody:
            oldBodySet = set(vulBody['old_body'])

        # 对每个目标函数进行检测
        for file in tarFuncs:
            x = set(tarFuncs[file]["norm"])  # 标准化函数体
            y = set(tarFuncs[file]["abst"])  # 抽象化函数体
            
            step = 1

            # 处理不同类型的漏洞
            if flag == 1 or flag == 2:
                # 补丁包含添加和删除的代码行

                if isAbs == 1:
                    # 使用抽象匹配

                    # 检查核心漏洞行
                    if not coreAbsVulLines.issubset(y):
                        step = 0

                    # 检查依赖行
                    if step == 1:
                        now = time.time()
                        for absLine in absDepens_withoutOLD:
                            if absLine not in y:
                                step = 0
                                break

                        # 尝试旧版本依赖
                        if step == 0 and len(absDepens_withOLD) > 0:
                            step = 1
                            for absLine in absDepens_withOLD:
                                if absLine not in y:
                                    step = 0
                                    break
                        mtime += time.time() - now

                    # 检查补丁特征
                    if step == 1 and flag == 2:
                        now = time.time()
                        if not newAbsPat.isdisjoint(y):
                            step = 0
                        mtime += time.time() - now

                    # 计算相似度
                    if step == 1:
                        now = time.time()
                        if len(vulBodySet) <= 3:
                            continue

                        # 检查与漏洞函数的相似度
                        if float(len(vulBodySet&x)/len(vulBodySet)) >= theta:
                            print ('\t* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                            continue
                        mtime += time.time() - now

                        try:
                            # 检查与最老漏洞函数的相似度
                            now = time.time()
                            if float(len(oldBodySet&x)/len(oldBodySet)) >= theta:
                                print ('\t* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                            mtime += time.time() - now
                        except:
                            pass

                else:
                    # 不使用抽象匹配

                    # 检查核心漏洞行
                    now = time.time()
                    if not coreVulLines.issubset(x):
                        step = 0                    
                    mtime += time.time() - now

                    # 检查依赖行
                    if step == 1:
                        now = time.time()
                        for absLine in norDepens_withoutOLD:
                            if absLine not in x:
                                step = 0
                                break

                        # 尝试旧版本依赖
                        if step == 0 and len(norDepens_withOLD) > 0:
                            step = 1
                            for absLine in norDepens_withOLD:
                                if absLine not in x:
                                    step = 0
                                    break
                        mtime += time.time() - now
                    
                    # 检查补丁特征
                    if step == 1 and flag == 2:
                        now = time.time()
                        if not newPat.isdisjoint(x):
                            step = 0
                        mtime += time.time() - now

                    # 计算相似度
                    if step == 1:
                        if len(vulBodySet) <= 3: 
                            continue
                        now = time.time()
                        if float(len(vulBodySet&x)/len(vulBodySet)) >= theta:
                            print ('\t* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                            continue
                        
                        mtime += time.time() - now

                        try:
                            # 检查与最老漏洞函数的相似度
                            now = time.time()
                            if float(len(oldBodySet&x)/len(oldBodySet)) >= theta:
                                print ('\t* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                            mtime += time.time() - now
                        except:
                            pass
    
            elif flag == 3:
                # 没有删除的代码行

                if (len(newAbsPat) == 0):
                    continue

                # 检查补丁特征
                now = time.time()            
                if not newAbsPat.isdisjoint(y):
                    step = 0
                mtime += time.time() - now

                # 计算相似度
                if step == 1:
                    if len(vulBodySet) <= 3: 
                        continue

                    now =time.time()
                    if float(len(vulBodySet&x)/len(vulBodySet)) >= theta:
                        print ('\t* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                        continue
                    mtime += time.time() - now

                    try:
                        # 检查与最老漏洞函数的相似度
                        now = time.time()
                        if float(len(oldBodySet&x)/len(oldBodySet)) >= theta:
                            print ('\t* [' + idx2ver[idx] + '] ' + tar + ' contains the vulnerable "' + file.split('##')[0] + '" function in ' + file.split('##')[1].replace('@@', '/'))
                        mtime += time.time() - now
                    except:
                        pass

            else:
                continue

    print ()
    print ("[+] TOTAL ELAPSED TIME (ONLY FOR VULNERABILITY DETECTION): " + str(mtime) + " s")

def main(target):
    """主函数,调用漏洞检测器"""
    detector(target)

"""程序入口"""
if __name__ == "__main__":
    # 获取命令行参数
    target = sys.argv[1]  # 目标程序
    testmd = sys.argv[2]  # 测试模式

    # 验证测试模式参数
    if testmd != '1' and testmd != '0':
        print ("Please enter correct inputs.")
        print ("python3 Detector.py 'TARGET_PROGRAM' [0|1]")
        sys.exit()
    
    # 处理测试模式
    if testmd == '1':
        # 预定义的可用目标程序列表
        currentPossible = ["arangodb", "crown", "emscripten", "ffmpeg", "freebsd-src", 
                          "git", "opencv", "openMVG", "reactos", "redis"]
        if target not in currentPossible:
            print ("Please enter one of the inputs below.")
            print (str(currentPossible))
            sys.exit()
        else:
            main(target)
    else:
        main(target)
