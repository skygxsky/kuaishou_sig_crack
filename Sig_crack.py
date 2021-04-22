import frida
from hashlib import sha256
from loguru import logger
from urllib.parse import unquote

class SigCrack(object):

    def __init__(self,url,data,login_token):
        self.url = url
        self.data = data
        self.login_token = login_token
        self.sig_result = {}
        self.data_result = ''

    def get_sig(self):
        hook_code = '''
        rpc.exports = {
            getsig: function(a,b){
                Java.perform(function() {
                        var currentApp = Java.use("android.app.ActivityThread").currentApplication();                
        	            var context = currentApp.getApplicationContext();       
                        var myHook = Java.use('生成sig签名的方法');                
                        var result = myHook.$new().getClock(context, a, b);
                        send(result)
                }
            )
            }
        };
        '''
        process = frida.get_usb_device(100).attach('app包名')
        script = process.create_script(hook_code)
        script.on('message', self.on_message)
        script.load()
        a = self.change_ASCII()
        b = 23
        script.exports.getsig(a,b)

    def get_sig3(self):
        hook_code = '''
        rpc.exports = {
            getsig: function(a){
                Java.perform(function() {      
                        var myHook = Java.use('生成sig3签名的类');                
                        var result = myHook.方法名(a);
                        send(result)
                }
            )
            }
        };
        '''
        process = frida.get_usb_device(100).attach('app包名')
        script = process.create_script(hook_code)
        script.on('message', self.message)
        script.load()
        a = '你访问接口的部分url' + self.sig_result['sig']
        script.exports.getsig(a)

    def on_message(self, message, data):
        if message['type'] == 'send':
            self.sig_result['sig'] = message['payload']
        elif message['type'] == 'error':
            logger.error(message['stack'])


    def message(self, message, data):
        if message['type'] == 'send':
            self.sig_result['__NS_sig3'] = message['payload']
        elif message['type'] == 'error':
            logger.error(message['stack'])

    def handle_url(self,arg):
        """
        url 转成列表
        :param arg:
        :return:
        """
        a = unquote(arg.split('?')[-1])
        a = a.split("&")
        a.sort()
        return a

    def handle_data(self, args):
        """
        data转成列表
        :param args:
        :return:
        """
        return unquote(args).split("&")

    def change_ASCII(self):
        """
        生成字符数组
        :return:
        """
        res = self.handle_url(self.url) + self.handle_data(self.data)
        res.sort()
        b = []
        for i in ''.join(res):
            b.append(ord(i))
        return b

    def get_NStokensig(self):
        """
        获取NStokensig
        :return:
        """
        text = self.sig_result['sig'] + self.login_token
        sha = sha256()
        sha.update(text.encode("utf-8"))
        self.sig_result['__NStokensig'] = sha.hexdigest()

    def get_result(self):
        """
        获得结果
        :return:
        """
        self.get_sig()
        self.get_sig3()
        self.get_NStokensig()
        return self.data + "&sig=" + self.sig_result['sig'] + "&__NS_sig3=" + self.sig_result['__NS_sig3'] + "&__NStokensig=" + self.sig_result['__NStokensig']


if __name__ == '__main__':
    url = 'charles 抓包完整的 url'
    data = 'charles 抓包完整的 form 表单信息'
    login_token = '账号登录后返回的token 是唯一的'
    obj = SigCrack(url,data,login_token)
    print(obj.get_result())