# -

此代码是一个反向IP查找域名工具，它可以对指定的URL或包含多个URL的文件进行反向IP查找，并在爱站和ip138网站上检查与之关联的域名，并返回其状态码和标题。该脚本使用的是Python语言编写，使用以下命令安装依赖库：
```pip install -r requirements.txt
```
使用方法
查询单个IP：
```
python3 reverse.py -u IP地址
```
查询多个IP需要将ip放入txt文件里：
```
python3 reverse.py -f 文件名
```
批量查询则将结果写入output.txt文本中
