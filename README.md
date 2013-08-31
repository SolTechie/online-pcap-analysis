OnlinePcapAnalysis   (http://121.199.35.74)
==================

一个在线的pcap文件分析工具

部署系统        ubuntu

http服务器      nginx+uwsgi

web框架         django

客户端支持      chrome safari firefox


部署方法：

mytask文件夹中是所有的程序代码，将其部署至~/目录下。

nginx_etx目录中是nginx的部署文件，主要修改nginx.conf和conf.d/default.conf文件，指明静态目录与Django网关，并且设置最大接受post上传的body。

wsgi.ini是uwsgi的启动配置文件。pingansz中是数据分析模块的代码。

最后启动nginx和uwsgi即可运行系统。
