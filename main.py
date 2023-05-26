import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import urllib.request
import base64
import json
import subprocess
import threading
import queue
import os
import datetime


class ChildProcHttpGet(threading.Thread):

    def __init__(self, url):
        threading.Thread.__init__(self)
        self.url = url
        self.ret = b''

    def run(self):
        try:
            print(f'system proxy: {urllib.request.getproxies()}')
            req = urllib.request.Request(self.url)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            response = opener.open(req)
            self.ret = response.read()
        except Exception as e:
            print(e)


def parse_svrs(data):
    print(f'original data: {data}')
    data = base64.b64decode(data)
    print(f'decoded data: {data}')
    data_lst = data.split(b'\n')
    print('data list:')
    for it in data_lst:
        print(it)

    svr_lst = []

    for it in data_lst:
        if it.startswith(b'ss://'):
            info, name = it[len(b'ss://'):].split(b'#')
            info = base64.b64decode(info + b'=' * (-len(info) % 4))
            info = info.decode('UTF-8')
            print(f'ss info: {info}')
            svr = {'type': 'ss', 'name': name.decode('UTF-8')}
            check, domain = info.split('@')
            svr['addr'], svr['port'] = domain.split(':')
            svr['cipher'], svr['password'] = check.split(':')
            print(f'ss svr: {svr}')
            svr_lst.append(svr)

        elif it.startswith(b'vmess://'):
            info = it[len(b'vmess://'):]
            info = base64.b64decode(info + b'=' * (-len(info) % 4))
            info = info.decode('UTF-8')
            print(f'vmess info: {info}')
            svr = {'type': 'vmess'}
            d = json.loads(info)
            svr['name'] = d['ps']
            svr['addr'] = d['add']
            svr['port'] = d['port']
            svr['id'] = d['id']
            svr['aid'] = d['aid']
            svr['network'] = d['net']
            if 'tls' in d and d['tls'] == 'tls':
                svr['security'] = d['tls']
                if 'sni' in d:
                    svr['servername'] = d['sni']
            print(f'vmess svr: {svr}')
            svr_lst.append(svr)

    return svr_lst


g_default_socks_port = 10808
g_default_http_port = 10809


class ConfigObj:

    def __init__(self):
        self.socks_port = g_default_socks_port
        self.http_port = g_default_http_port
        self.global_proxy = False

    def gen_json(self, svr):
        d = {}

        log = {'access': '', 'error': '', 'loglevel': 'warning'}
        d['log'] = log

        inbound0 = {'tag': 'socks', 'port': self.socks_port, 'listen': '127.0.0.1', 'protocol': 'socks'}
        sniffing = {'enabled': True, 'destOverride': ['http', 'tls']}
        settings = {'auth': 'noauth', 'udp': True, 'allowTransparent': False}
        inbound0['sniffing'] = sniffing
        inbound0['settings'] = settings

        inbound1 = {'tag': 'http', 'port': self.http_port, 'listen': '127.0.0.1', 'protocol': 'http'}
        sniffing = {'enabled': True, 'destOverride': ['http', 'tls']}
        settings = {'auth': 'noauth', 'udp': True, 'allowTransparent': False}
        inbound1['sniffing'] = sniffing
        inbound1['settings'] = settings

        d['inbounds'] = [inbound0, inbound1]

        outbound0 = {'tag': 'proxy'}
        if svr['type'] == 'ss':
            outbound0['protocol'] = 'shadowsocks'
            server0 = {'address': svr['addr'], 'port': int(svr['port']), 'ota': False,
                       'method': svr['cipher'], 'password': svr['password'], 'level': 1}
            outbound0['settings'] = {'servers': [server0, ]}
            outbound0['streamSettings'] = {'network': 'tcp'}
            outbound0['mux'] = {'enabled': False, 'concurrency': -1}
        elif svr['type'] == 'vmess':
            outbound0['protocol'] = 'vmess'
            vnext0 = {'address': svr['addr'], 'port': int(svr['port']),
                      'users': [{'id': svr['id'], 'alterId': svr['aid'], 'email': 't@t.tt', 'security': 'auto'}, ]}
            outbound0['settings'] = {'vnext': [vnext0, ]}
            outbound0['streamSettings'] = {'network': svr['network']}
            outbound0['mux'] = {'enabled': False, 'concurrency': -1}
            if 'security' in svr and 'servername' in svr:
                outbound0['streamSettings']['security'] = svr['security']
                outbound0['streamSettings']['tlsSettings'] = \
                    {'allowInsecure': True, 'serverName': svr['servername'], 'fingerprint': ''}
        else:
            return None

        outbound1 = {'tag': 'direct', 'protocol': 'freedom', 'settings': {}}
        outbound2 = {'tag': 'block', 'protocol': 'blackhole', 'settings': {'response': {'type': 'http'}}}

        d['outbounds'] = [outbound0, outbound1, outbound2]

        routing = {'domainStrategy': 'IPIfNonMatch'}
        rule0 = {'type': 'field', 'inboundTag': ['api', ], 'outboundTag': 'api', 'enabled': True}
        rule1 = {'type': 'field', 'outboundTag': 'direct', 'enabled': True,
                 'domain': ['domain:example-example.com', 'domain:example-example2.com']}
        rule2 = {'type': 'field', 'outboundTag': 'block', 'enabled': True,
                 'domain': ['geosite:category-ads-all', ]}
        rule3 = {'type': 'field', 'outboundTag': 'direct', 'enabled': True,
                 'domain': ['geosite:cn', ]}
        rule4 = {'type': 'field', 'outboundTag': 'direct', 'enabled': True,
                 'ip': ['geoip:private', 'geoip:cn']}
        rule5 = {'type': 'field', 'port': '0-65535', 'outboundTag': 'proxy', 'enabled': True}
        if self.global_proxy:
            routing['rules'] = [rule0, rule5]
        else:
            routing['rules'] = [rule0, rule1, rule2, rule3, rule4, rule5]

        d['routing'] = routing

        return json.dumps(d, indent=2)


class SubProcReader(threading.Thread):

    def __init__(self, fd, q):
        threading.Thread.__init__(self)
        self.fd = fd
        self.q = q

    def run(self):
        try:
            while 1:
                line = self.fd.readline()
                if len(line) <= 0:
                    break
                self.q.put(line.decode('UTF-8'))
        except Exception as e:
            print(e)


class UIMain:

    def __init__(self):
        self.http_get = None
        self.svr_lst = []
        self.cur_svr = -1
        self.cur_popup = 0
        self.config_obj = ConfigObj()

        self.process = None
        self.out_q = None
        self.err_q = None
        self.out_t = None
        self.err_t = None

        user_url = ''
        user_path = ''
        user_file = os.path.join(os.path.expanduser('~'), 'maybeuseful.json')
        if os.path.exists(user_file):
            f_user = open(user_file, 'rb')
            data = f_user.read().decode('UTF-8')
            f_user.close()
            data = json.loads(data)
            user_url = data.get('user_url', '')
            user_path = data.get('user_path', '')

        self.root = tk.Tk()
        self.root.title('hello python')
        self.root.protocol('WM_DELETE_WINDOW', self.root_close)

        self.frame = tk.Frame(self.root)
        self.frame.pack(fill='both')

        self.frame_table = tk.Frame(self.frame)
        self.frame_table.pack(fill='x', side='top', padx=5, pady=5)

        self.table_vs = ttk.Scrollbar(self.frame_table, orient='vertical')
        self.table_vs.pack(fill='y', side='right')
        self.table_hs = ttk.Scrollbar(self.frame_table, orient='horizontal')
        self.table_hs.pack(fill='x', side='bottom')

        self.table = ttk.Treeview(self.frame_table, selectmode='browse',
                                  yscrollcommand=self.table_vs.set,
                                  xscrollcommand=self.table_hs.set)
        self.table_vs.config(command=self.table.yview)
        self.table_hs.config(command=self.table.xview)
        self.table.pack(fill='x', side='top')

        self.frame0 = tk.Frame(self.frame)
        self.frame0.pack(fill='x', side='top')

        self.label_url = tk.Label(self.frame0, text='URL:')
        self.label_url.pack(side='left', padx=5, pady=2)

        self.editor_url = tk.Entry(self.frame0)
        self.editor_url.pack(fill='x', side='left', expand=True, padx=5, pady=2)
        if len(user_url) > 0:
            self.editor_url.insert(0, user_url)

        self.btn_update = tk.Button(self.frame0, text='Update Subscription',
                                    command=self.click_update_subscription)
        self.btn_update.pack(side='right', padx=5, pady=2)

        self.frame1 = tk.Frame(self.frame)
        self.frame1.pack(fill='x', side='top')

        self.label_path = tk.Label(self.frame1, text='V2Ray PATH:')
        self.label_path.pack(side='left', padx=5, pady=2)

        self.editor_path = tk.Entry(self.frame1)
        self.editor_path.pack(fill='x', side='left', expand=True, padx=5, pady=2)
        if len(user_path) > 0:
            self.editor_path.insert(0, user_path)

        self.check_error_var = tk.IntVar()
        self.check_error = tk.Checkbutton(self.frame1, text='show error', variable=self.check_error_var,
                                          onvalue=1, offvalue=0, command=self.click_check_error)
        self.check_error.pack(side='right', padx=5, pady=2)

        self.check_global_var = tk.IntVar()
        self.check_global = tk.Checkbutton(self.frame1, text='Global Proxy', variable=self.check_global_var,
                                           onvalue=1, offvalue=0)
        self.check_global.pack(side='right', padx=5, pady=2)

        self.editor_http_port = tk.Entry(self.frame1, width=8)
        self.editor_http_port.pack(side='right', padx=(0, 5), pady=2)
        self.editor_http_port.insert(0, str(g_default_http_port))

        self.label_http_port = tk.Label(self.frame1, text='http-port:')
        self.label_http_port.pack(side='right', padx=(5, 0), pady=2)

        self.editor_socks_port = tk.Entry(self.frame1, width=8)
        self.editor_socks_port.pack(side='right', padx=(0, 5), pady=2)
        self.editor_socks_port.insert(0, str(g_default_socks_port))

        self.label_socks_port = tk.Label(self.frame1, text='socks-port:')
        self.label_socks_port.pack(side='right', padx=(5, 0), pady=2)

        self.frame_out = tk.Frame(self.frame)
        self.frame_out.pack(fill='x', side='top', padx=5, pady=5)

        self.label_stdout = tk.Label(self.frame_out, text='std out:')
        self.label_stdout.pack(side='top', anchor='nw')

        self.text_stdout_vs = tk.Scrollbar(self.frame_out, orient='vertical')
        self.text_stdout_vs.pack(fill='y', side='right')
        self.text_stdout_hs = tk.Scrollbar(self.frame_out, orient='horizontal')
        self.text_stdout_hs.pack(fill='x', side='bottom')

        self.text_stdout = tk.Text(self.frame_out, height=10, wrap='none',
                                   yscrollcommand=self.text_stdout_vs.set,
                                   xscrollcommand=self.text_stdout_hs.set)
        self.text_stdout_vs.config(command=self.text_stdout.yview)
        self.text_stdout_hs.config(command=self.text_stdout.xview)
        self.text_stdout.pack(fill='x', side='top')

        self.frame_err = tk.Frame(self.frame)
        self.frame_err.pack(fill='x', side='top', padx=5, pady=5)

        self.label_stderr = tk.Label(self.frame_err, text='std err:')
        self.label_stderr.pack(side='top', anchor='nw')

        self.text_stderr_vs = tk.Scrollbar(self.frame_err, orient='vertical')
        self.text_stderr_vs.pack(fill='y', side='right')
        self.text_stderr_hs = tk.Scrollbar(self.frame_err, orient='horizontal')
        self.text_stderr_hs.pack(fill='x', side='bottom')

        self.text_stderr = tk.Text(self.frame_err, height=10, wrap='none',
                                   yscrollcommand=self.text_stderr_vs.set,
                                   xscrollcommand=self.text_stderr_hs.set)
        self.text_stderr_vs.config(command=self.text_stderr.yview)
        self.text_stderr_hs.config(command=self.text_stderr.xview)
        self.text_stderr.pack(fill='x', side='top')

        self.table_popup = tk.Menu(self.root, tearoff=0)
        self.table_popup.add_command(label='Use This', command=self.table_popup_select)
        self.table_popup.add_command(label='Do Not Use This', command=self.table_popup_unselect)
        self.table_popup.add_separator()
        self.table_popup.add_command(label='Test Speed', command=self.table_popup_speed)

        self.table['columns'] = ('NAME', 'TYPE', 'ADDR', 'PORT', 'CIPHER', 'NETWORK', 'SECURITY', 'SERVERNAME')

        self.table.column('#0', anchor=tk.CENTER, width=40, stretch=False)
        self.table.column('NAME', anchor=tk.CENTER, width=60, stretch=False)
        self.table.column('TYPE', anchor=tk.CENTER, width=60, stretch=False)
        self.table.column('ADDR', anchor=tk.CENTER, width=60, stretch=False)
        self.table.column('PORT', anchor=tk.CENTER, width=60, stretch=False)
        self.table.column('CIPHER', anchor=tk.CENTER, width=80, stretch=False)
        self.table.column('NETWORK', anchor=tk.CENTER, width=80, stretch=False)
        self.table.column('SECURITY', anchor=tk.CENTER, width=80, stretch=False)
        self.table.column('SERVERNAME', anchor=tk.CENTER, width=100, stretch=False)

        self.table.heading('#0', text='', anchor=tk.CENTER)
        self.table.heading('NAME', text='NAME', anchor=tk.CENTER)
        self.table.heading('TYPE', text='TYPE', anchor=tk.CENTER)
        self.table.heading('ADDR', text='ADDR', anchor=tk.CENTER)
        self.table.heading('PORT', text='PORT', anchor=tk.CENTER)
        self.table.heading('CIPHER', text='CIPHER', anchor=tk.CENTER)
        self.table.heading('NETWORK', text='NETWORK', anchor=tk.CENTER)
        self.table.heading('SECURITY', text='SECURITY', anchor=tk.CENTER)
        self.table.heading('SERVERNAME', text='SERVERNAME', anchor=tk.CENTER)

        self.table.bind('<Button-2>', self.do_table_popup)  # for mac
        self.table.bind('<Button-3>', self.do_table_popup)  # for win

        self.root.update()
        self.min_sz = (self.frame.winfo_width(), self.frame.winfo_height())
        self.frame_err.pack_forget()
        self.root.update()
        self.min_sz_noerr = (self.frame.winfo_width(), self.frame.winfo_height())
        self.root.minsize(self.min_sz_noerr[0], self.min_sz_noerr[1])

    def root_close(self):
        print('root close')
        self.stop_v2ray()
        self.root.destroy()

    def click_update_subscription(self):
        if self.http_get:
            print('Subscriptions are currently being updated')
            return

        url = self.editor_url.get()
        if len(url) <= 0:
            messagebox.showinfo('update subscription', 'url is empty')
            return

        self.stop_v2ray()
        self.svr_lst = []
        self.cur_svr = -1
        self.cur_popup = 0
        self.update_svr_lst_to_ui()

        print(f'Start update subscription: {url}')
        self.http_get = ChildProcHttpGet(url)
        self.http_get.start()
        self.root.after(100, func=self.check_update_subscription)

    def check_update_subscription(self):
        if self.http_get and self.http_get.is_alive():
            self.root.after(100, func=self.check_update_subscription)
            print('Wait...')
            return

        if self.http_get:
            print(f'Update subscription returns: {self.http_get.ret}')
            self.svr_lst = parse_svrs(self.http_get.ret)
            self.http_get = None
            self.update_svr_lst_to_ui()

    def update_svr_lst_to_ui(self):
        self.table.delete(*self.table.get_children())

        cur_iid = 0
        check = '⚫'
        uncheck = '⚪'
        for it in self.svr_lst:
            val = (it.get('name', ''),
                   it.get('type', ''),
                   it.get('addr', ''),
                   it.get('port', ''),
                   it.get('cipher', ''),
                   it.get('network', ''),
                   it.get('security', ''),
                   it.get('servername', ''))
            self.table.insert(parent='', index='end', iid=cur_iid,
                              text=(check if cur_iid == self.cur_svr else uncheck), values=val)
            cur_iid += 1

    def click_check_error(self):
        print(f'click check global: {self.check_error_var.get()}')
        if self.check_error_var.get() == 1:
            self.frame_err.pack(fill='x', side='top', padx=5, pady=5)
            self.root.minsize(self.min_sz[0], self.min_sz[1])
        else:
            self.frame_err.pack_forget()
            self.root.minsize(self.min_sz_noerr[0], self.min_sz_noerr[1])

    def do_table_popup(self, event):
        iid = self.table.identify_row(event.y)
        if len(iid) > 0:
            self.cur_popup = int(iid)
            self.table_popup.post(event.x_root, event.y_root)

    def table_popup_select(self):
        if self.cur_popup < 0 or self.cur_popup >= len(self.svr_lst):
            return

        self.cur_svr = self.cur_popup
        self.start_v2ray()

        if not self.process:
            self.cur_svr = -1

        self.update_svr_lst_to_ui()

    def table_popup_unselect(self):
        if self.cur_popup < 0 or self.cur_popup >= len(self.svr_lst):
            return

        if self.cur_svr == self.cur_popup:
            self.cur_svr = -1
            self.stop_v2ray()

        self.update_svr_lst_to_ui()

    def table_popup_speed(self):
        pass

    def subproc_data(self):
        if self.out_q is None or self.err_q is None:
            return

        a = datetime.datetime.now()
        while not self.out_q.empty():
            line = self.out_q.get()
            self.text_stdout.insert(tk.END, line)
            if self.text_stdout_vs.get()[1] == 1.0:
                self.text_stdout.yview_pickplace('end')
            b = datetime.datetime.now() - a
            if b.microseconds > 200:
                break

        a = datetime.datetime.now()
        while not self.err_q.empty():
            line = self.err_q.get()
            self.text_stderr.insert(tk.END, line)
            if self.text_stderr_vs.get()[1] == 1.0:
                self.text_stderr.yview_pickplace('end')
            b = datetime.datetime.now() - a
            if b.microseconds > 200:
                break

        max_line = 2000

        total = int(self.text_stdout.index(tk.END).split('.')[0])
        if total > max_line:
            self.text_stdout.delete('1.0', f'{total - max_line + 1}.0')
            if self.text_stdout_vs.get()[1] == 1.0:
                self.text_stdout.yview_pickplace('end')

        total = int(self.text_stderr.index(tk.END).split('.')[0])
        if total > max_line:
            self.text_stderr.delete('1.0', f'{total - max_line + 1}.0')
            if self.text_stderr_vs.get()[1] == 1.0:
                self.text_stderr.yview_pickplace('end')

        self.root.after(1000, self.subproc_data)

    def start_v2ray(self):
        print('start v2ray')

        self.stop_v2ray()

        path = self.editor_path.get()
        if len(path) <= 0:
            messagebox.showinfo('start v2ray', 'path is empty')
            return

        socks_port = self.editor_socks_port.get()
        if socks_port.isdigit():
            self.config_obj.socks_port = int(socks_port)
        else:
            messagebox.showinfo('start v2ray', 'socks port error')
            return

        http_port = self.editor_http_port.get()
        if http_port.isdigit():
            self.config_obj.http_port = int(http_port)
        else:
            messagebox.showinfo('start v2ray', 'http port error')
            return

        self.config_obj.global_proxy = (self.check_global_var.get() == 1)

        print(f'socks_port: {self.config_obj.socks_port}, '
              f'http_port: {self.config_obj.http_port}, '
              f'global_proxy: {self.config_obj.global_proxy}')

        exe_path = os.path.join(path, 'wv2ray.exe')
        if not os.path.exists(exe_path):
            exe_path = os.path.join(path, 'v2ray')
        if not os.path.exists(exe_path):
            messagebox.showinfo('start v2ray', 'v2ray can not found')
            return

        if self.cur_svr < 0 or self.cur_svr >= len(self.svr_lst):
            messagebox.showinfo('start v2ray', 'server index incorrect')
            return

        config_path = os.path.join(path, 'config.json')
        cur_json = self.config_obj.gen_json(self.svr_lst[self.cur_svr])
        f = open(config_path, 'wb')
        f.write(cur_json.encode('UTF-8'))
        f.close()

        self.process = subprocess.Popen([exe_path, ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.out_q = queue.Queue()
        self.err_q = queue.Queue()

        self.out_t = SubProcReader(self.process.stdout, self.out_q)
        self.out_t.start()

        self.err_t = SubProcReader(self.process.stderr, self.err_q)
        self.err_t.start()

        self.subproc_data()

        data = {'user_url': self.editor_url.get(), 'user_path': self.editor_path.get()}
        data = json.dumps(data, indent=2)
        user_file = os.path.join(os.path.expanduser('~'), 'maybeuseful.json')
        f_user = open(user_file, 'wb')
        f_user.write(data.encode('UTF-8'))
        f_user.close()

    def stop_v2ray(self):
        print('stop v2ray')

        if self.process:
            self.process.kill()
            self.process = None
            self.out_q = None
            self.err_q = None

            print('wait std out queue exit')
            self.out_t.join()
            self.out_t = None

            print('wait std err queue exit')
            self.err_t.join()
            self.err_t = None

            print('stop v2ray finish')


if __name__ == '__main__':
    ui_main = UIMain()
    ui_main.root.mainloop()
