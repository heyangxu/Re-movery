"""
MOVERY 预处理器
作者:     Seunghoon Woo (seunghoonwoo@korea.ac.kr)
修改日期: March 31, 2023.

主要功能：
1. 处理目标代码仓库中的C/C++源文件
2. 提取所有函数并进行标准化处理
3. 生成函数的多种表示形式(原始、标准化、抽象化)
4. 输出处理后的函数信息和哈希值

工作流程：
1. 接收目标代码仓库路径
2. 遍历所有C/C++源文件
3. 使用ctags提取函数信息
4. 对每个函数进行三重处理：
   - 保存原始代码
   - 生成标准化版本
   - 生成抽象化版本
5. 输出处理结果：
   - 函数信息JSON文件
   - 函数哈希值文件
"""

# 导入必要的库
import os
import sys
currentPath = os.getcwd()
sys.path.append(currentPath + "/config/")  # 添加配置文件路径
import subprocess  # 用于执行ctags命令
import re          # 用于正则表达式处理
import json        # 用于JSON数据处理
import time
from hashlib import md5  # 用于生成哈希值

"""全局变量配置"""
# 支持的源代码文件扩展名
possible = (".c", ".cc", ".cpp")  
# 用于分隔不同部分的特殊字符序列
delimiter = "\r\0?\r?\0\r"        

"""路径配置"""
# 处理后的函数存储路径
targetPath = currentPath + "/dataset/tarFuncs/"    
# ctags工具的路径，用于代码分析
pathToCtags = '/home/MOVERY/config/ctags'         

"""工具函数"""
def intersect(a, b):
    """计算两个列表的交集
    参数:
        a, b: 输入列表
    返回:
        两个列表的交集
    """
    return list(set(a) & set(b))

def union(a, b):
    """计算两个列表的并集
    参数:
        a, b: 输入列表
    返回:
        两个列表的并集
    """
    return list(set(a) | set(b))

def jaccard_sim(a, b):
    """计算Jaccard相似度
    用于衡量两个集合的相似度，计算公式：交集大小/并集大小
    
    参数:
        a, b: 要比较的两个集合
    返回:
        相似度值（0-1之间的浮点数）
    """
    inter = len(list(set(a).intersection(b)))
    union = (len(set(a)) + len(b)) - inter
    return float(inter) / union

def normalize(string):
    """标准化字符串
    1. 移除回车符和制表符
    2. 移除所有空格
    3. 转换为小写
    
    参数:
        string: 输入字符串
    返回:
        标准化后的字符串
    """
    return ''.join(string.replace('\r', '').replace('\t', '').split(' ')).lower()

def normalize_hash(string):
    """用于哈希计算的标准化
    比普通标准化多移除了换行符和花括号
    
    参数:
        string: 输入字符串
    返回:
        用于哈希计算的标准化字符串
    """
    return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(' ')).lower()

def abstract(body, ext):
    """函数体抽象化处理
    1. 使用ctags分析代码结构
    2. 识别局部变量、参数和数据类型
    3. 将这些标识符替换为通用标记(FPARAM/DTYPE/LVAR)
    
    处理流程：
    1. 创建临时文件存储函数体
    2. 使用ctags分析代码结构
    3. 识别并收集所有变量、参数和类型
    4. 依次替换为对应的抽象标记
    
    参数:
        body: 函数体字符串
        ext: 文件扩展名
    返回:
        抽象化后的函数体
    """
    global delimiter

    # 创建临时文件
    tempFile = './dataset/temp/temp.' + ext
    ftemp = open(tempFile, 'w', encoding="UTF-8")
    ftemp.write(body)
    ftemp.close()

    abstractBody = ""
    originalFunctionBody = body
    abstractBody = originalFunctionBody

    # 使用ctags分析代码
    command = pathToCtags + ' -f - --kinds-C=* --fields=neKSt "' + tempFile + '"'
    try:
        astString = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True).decode(errors='ignore')
    except subprocess.CalledProcessError as e:
        print ("Parser Error:", e)
        astString = ""

    # 初始化存储列表
    variables = []    # 存储局部变量
    parameters = []   # 存储参数
    dataTypes = []    # 存储数据类型

    # 编译正则表达式模式
    functionList = astString.split('\n')
    local = re.compile(r'local')
    parameter = re.compile(r'parameter')
    func = re.compile(r'(function)')
    parameterSpace = re.compile(r'\(\s*([^)]+?)\s*\)')
    word = re.compile(r'\w+')
    dataType = re.compile(r"(typeref:)\w*(:)")
    number = re.compile(r'(\d+)')
    funcBody = re.compile(r'{([\S\s]*)}')

    lines = []
    parameterList = []
    dataTypeList = []
    variableList = []

    # 解析ctags输出，收集变量信息
    for i in functionList:
        elemList = re.sub(r'[\t\s ]{2,}', '', i)
        elemList = elemList.split("\t")
        if i != '' and len(elemList) >= 6 and (local.fullmatch(elemList[3]) or local.fullmatch(elemList[4])):
            variables.append(elemList)
        
        if i != '' and len(elemList) >= 6 and (parameter.match(elemList[3]) or parameter.fullmatch(elemList[4])):
            parameters.append(elemList)

    # 处理函数定义
    for i in functionList:
        elemList = re.sub(r'[\t\s ]{2,}', '', i)
        elemList = elemList.split('\t')
        if i != '' and len(elemList) >= 8 and func.fullmatch(elemList[3]):
            lines = (int(number.search(elemList[4]).group(0)), int(number.search(elemList[7]).group(0)))

            lineNumber = 0
            # 收集参数信息
            for param in parameters:
                if number.search(param[4]):
                    lineNumber = int(number.search(param[4]).group(0))
                elif number.search(param[5]):
                    lineNumber = int(number.search(param[5]).group(0))
                if len(param) >= 4 and lines[0] <= int(lineNumber) <= lines[1]:
                    parameterList.append(param[0])
                    if len(param) >= 6 and dataType.search(param[5]):
                        dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", param[5])))
                    elif len(param) >= 7 and dataType.search(param[6]):
                        dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", param[6])))

            # 收集变量信息
            for variable in variables:
                if number.search(variable[4]):
                    lineNumber = int(number.search(variable[4]).group(0))
                elif number.search(variable[5]):
                    lineNumber = int(number.search(variable[5]).group(0))
                if len(variable) >= 4 and lines[0] <= int(lineNumber) <= lines[1]:
                    variableList.append(variable[0])
                    if len(variable) >= 6 and dataType.search(variable[5]):
                        dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", variable[5])))
                    elif len(variable) >= 7 and dataType.search(variable[6]):
                        dataTypeList.append(re.sub(r" \*$", "", dataType.sub("", variable[6])))                        

    # 执行替换操作
    # 替换参数
    for param in parameterList:
        if len(param) == 0:
            continue
        try:
            paramPattern = re.compile("(^|\W)" + param + "(\W)")
            abstractBody = paramPattern.sub("\g<1>FPARAM\g<2>", abstractBody)
        except:
            pass

    # 替换数据类型
    for dtype in dataTypeList:
        if len(dtype) == 0:
            continue
        try:
            dtypePattern = re.compile("(^|\W)" + dtype + "(\W)")
            abstractBody = dtypePattern.sub("\g<1>DTYPE\g<2>", abstractBody)
        except:
            pass

    # 替换局部变量
    for lvar in variableList:
        if len(lvar) == 0:
            continue
        try:
            lvarPattern = re.compile("(^|\W)" + lvar + "(\W)")
            abstractBody = lvarPattern.sub("\g<1>LVAR\g<2>", abstractBody)
        except:
            pass
        
    # 清理临时文件
    os.remove(tempFile)
    return abstractBody

def removeComment(string):
    """移除C/C++风格的注释
    使用正则表达式匹配并移除单行注释和多行注释
    
    参数:
        string: 输入的代码字符串
    返回:
        移除注释后的代码字符串
    """
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])

def readFile(path):
    """读取文件内容
    尝试使用不同编码(UTF-8/CP949/euc-kr)读取文件
    
    参数:
        path: 文件路径
    返回:
        文件内容的行列表
    """
    body = ''
    # 依次尝试不同编码
    try:
        fp = open(path, 'r', encoding = "UTF-8")
        body = fp.readlines()
    except:
        try:
            fp = open(path, 'r', encoding = "CP949")
            body = fp.readlines()
        except:
            try:
                fp = open(path, 'r', encoding = "euc-kr")
                body = fp.readlines()
            except:
                pass
    return body

def preprocessor(target):
    """主要预处理函数
    1. 遍历目标目录下的所有源文件
    2. 提取每个文件中的所有函数
    3. 对每个函数进行三种处理：
       - 原始代码保存
       - 标准化处理
       - 抽象化处理
    4. 生成函数信息文件和哈希值文件
    
    处理流程：
    1. 初始化函数集合
    2. 遍历源文件
    3. 对每个文件：
       - 使用ctags提取函数
       - 处理每个函数
       - 生成多种表示形式
    4. 保存处理结果
    
    参数:
        target: 目标代码仓库路径
    """
    # 初始化存储所有函数信息的字典
    OSSfuncSet = {}

    # 遍历目标目录
    for path, dir, files in os.walk("./" + target):
        for file in files:
            filePath = os.path.join(path, file)
            ext = file.split('.')[-1]
            # 只处理C/C++文件
            if file.endswith(possible):
                try:
                    # 使用ctags分析文件
                    functionList = subprocess.check_output(pathToCtags + ' -f - --kinds-C=* --fields=neKSt "' + filePath + '"', 
                                                        stderr=subprocess.STDOUT, shell=True).decode()
                    lines = readFile(filePath)

                    allFuncs = str(functionList).split('\n')
                    func = re.compile(r'(function)')
                    number = re.compile(r'(\d+)')
                    funcSearch = re.compile(r'{([\S\s]*)}')
                    tmpString = ""
                    funcBody = ""

                    # 处理每个函数
                    for i in allFuncs:
                        elemList = re.sub(r'[\t\s ]{2,}', '', i)
                        elemList = elemList.split('\t')
                        funcBody = ""

                        if i != '' and len(elemList) >= 8 and func.fullmatch(elemList[3]):
                            # 提取函数信息
                            funcName = elemList[0]
                            funcStartLine = int(number.search(elemList[4]).group(0))
                            funcEndLine = int(number.search(elemList[7]).group(0))

                            # 获取函数体
                            tmpString = ""
                            tmpString = tmpString.join(lines[funcStartLine -1: funcEndLine])
                            rawBody = tmpString

                            # 生成函数哈希值
                            try:
                                funcHash = md5(rawBody.encode('utf-8')).hexdigest()
                            except:
                                try:
                                    funcHash = md5(rawBody.encode('cp949')).hexdigest()
                                except:
                                    try:
                                        funcHash = md5(rawBody.encode('euc-kr')).hexdigest()
                                    except:
                                        continue

                            # 生成函数标识符
                            newname = (funcName + '##' + '@@'.join(filePath.split(target+'/')[1].split('/')[0:]))    
                            # 生成抽象化版本
                            absBody = abstract(rawBody, ext)

                            # 存储函数的多种表示形式
                            OSSfuncSet[newname] = {}
                            OSSfuncSet[newname]['orig'] = []
                            OSSfuncSet[newname]['norm'] = []
                            OSSfuncSet[newname]['abst'] = []

                            if rawBody != '' and absBody != '':
                                # 存储原始代码
                                OSSfuncSet[newname]['orig'] = rawBody.split('\n')

                                # 生成标准化版本
                                noComment = removeComment(rawBody)
                                noAbsComment = removeComment(absBody)

                                # 存储标准化版本
                                for eachLine in noComment.split('\n'):
                                    OSSfuncSet[newname]['norm'].append(normalize(eachLine))

                                # 存储抽象化版本
                                for eachLine in noAbsComment.split('\n'):
                                    OSSfuncSet[newname]['abst'].append(normalize(eachLine))

                except subprocess.CalledProcessError as e:
                    print("Parser Error:", e)
                    print("Continue parsing..")
                    continue
                except Exception as e:
                    print ("Subprocess failed", e)
                    print("Continue parsing..")
                    continue

    # 保存处理结果
    # 保存函数信息到JSON文件
    data = json.dumps(OSSfuncSet)
    fsave = open('./dataset/tarFuncs/' + target + '_funcs.txt', 'w', encoding = "UTF-8")
    fsave.write(data)
    fsave.close()

    # 保存函数哈希值
    fsave_hash = open('./dataset/tarFuncs/' + target + '_hash.txt', 'w', encoding = "UTF-8")
    for each in OSSfuncSet:
        funcbody = normalize_hash(''.join(OSSfuncSet[each]['norm']))
        fsave_hash.write(md5(funcbody.encode('utf-8')).hexdigest() + '\t' + each + '\n')
    fsave_hash.close()

def main(target):
    """主函数
    启动预处理流程
    
    参数:
        target: 目标代码仓库路径
    """
    print ('Now MOVERY preprocesses the target repository.')
    print ('This requires several minutes...')
    preprocessor(target)

"""程序入口"""
if __name__ == "__main__":
    # 从命令行获取目标路径
    target = sys.argv[1]
    # 检查目标路径是否存在
    if not os.path.isdir('./'+target):
        print ("No target path.")
        sys.exit()
    # 启动处理流程
    main(target)
