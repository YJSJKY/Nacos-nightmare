# Nacos-nightmare
发现nacos漏洞的一体式扫描脚本
扫描包括{
弱口令
CVE-2021-29441（User-Agent 鉴权绕过）
QVD-2023-6271（token.secret.key 默认值）
CNVD-2020-67618（Derby SQL 注入可达性）
}
扫描完成后会在当前目录生成报告文件
使用方法
第0步，打开当前目录cmd命令行
第1步（根据需求选择方式）
    一、直接传URL          python nacos_readonly_check.py http://1.2.3.4:8848/nacos
    二、多个URL            python nacos_readonly_check.py http://a:8848/nacos http://b:8848 http://c:8848
    三、当前目录文件读取    python nacos_readonly_check.py --file urls.txt
    注意：urls.txt中一行一个url！！
最后一步，等待命令行执行结束，生成报告，即可查看报告
