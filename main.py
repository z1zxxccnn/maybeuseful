import tkinter as tk
from tkinter import ttk
import multiprocessing
import urllib.request
import base64
import json


def do_get(child_conn, url):
    response = urllib.request.urlopen(url)
    content = response.read()
    chunk_size = 1024 * 64
    for i in range(0, len(content), chunk_size):
        child_conn.send_bytes(content[i:i + chunk_size])
    child_conn.close()


class ChildProcHttpGet:
    def __init__(self, url):
        self.ret = b''
        self.eof = False
        self.parent_conn, child_conn = multiprocessing.Pipe()
        self.proc = multiprocessing.Process(target=do_get, args=(child_conn, url))
        self.proc.start()
        child_conn.close()

    def finish(self):
        if self.eof:
            return True

        try:
            while self.parent_conn.poll():
                try:
                    self.ret += self.parent_conn.recv_bytes()
                except EOFError:
                    self.eof = True
        except BrokenPipeError:
            self.eof = True

        return self.eof


def parse_svrs(data):
    print(f'original data: {data}')
    data = base64.b64decode(data)
    print(f'decoded data: {data}')
    data_lst = data.split(b'\n')
    print(f'data list:')
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


class ConfigObj:

    def __init__(self):
        self.socks_port = 10808
        self.http_port = 10809

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
            server0 = {'address': svr['addr'], 'port': svr['port'], 'ota': False,
                       'method': svr['cipher'], 'password': svr['password'], 'level': 1}
            outbound0['settings'] = {'servers': [server0, ]}
            outbound0['streamSettings'] = {'network': 'tcp'}
            outbound0['mux'] = {'enabled': False, 'concurrency': -1}
        elif svr['type'] == 'vmess':
            outbound0['protocol'] = 'vmess'
            vnext0 = {'address': svr['addr'], 'port': svr['port'],
                      'users': {'id': svr['id'], 'alterId': svr['aid'], 'email': 't@t.tt', 'security': 'auto'}}
            outbound0['settings'] = {'vnext': [vnext0, ]}
            outbound0['streamSettings'] = {'network': svr['network']}
            outbound0['mux'] = {'enabled': False, 'concurrency': -1}
            if 'tls' in svr and 'sni' in svr:
                outbound0['streamSettings']['security'] = svr['security']
                outbound0['streamSettings']['tlsSettings'] =\
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
        routing['rules'] = [rule0, rule1, rule2, rule3, rule4, rule5]

        d['routing'] = routing

        return json.dumps(d, indent=4)


class UIMain:

    def __init__(self):
        self.http_get = None
        self.svr_lst = []
        self.cur_svr = -1
        self.cur_popup = 0
        self.config_obj = ConfigObj()

        self.root = tk.Tk()
        self.root.title("hello python")

        self.frame = tk.Frame(self.root)
        self.frame.pack(fill='both')

        self.table = ttk.Treeview(self.frame)
        self.table.pack(fill='x', side='top')

        self.frame0 = tk.Frame(self.frame)
        self.frame0.pack(fill='x', side='top')

        self.editor_lab0 = tk.Label(self.frame0, text='URL:')
        self.editor_lab0.pack(side='left', padx=5, pady=2)

        self.editor0 = tk.Entry(self.frame0)
        self.editor0.pack(fill='x', side='left', expand=True, padx=5, pady=2)

        self.btn0 = tk.Button(self.frame0, text="Update Subscription", command=self.click_update_subscription)
        self.btn0.pack(side='right', padx=5, pady=2)

        self.frame1 = tk.Frame(self.frame)
        self.frame1.pack(fill='x', side='top')

        self.editor_lab1 = tk.Label(self.frame1, text='V2Ray PATH:')
        self.editor_lab1.pack(side='left', padx=5, pady=2)

        self.editor1 = tk.Entry(self.frame1)
        self.editor1.pack(fill='x', side='left', expand=True, padx=5, pady=2)

        self.table_popup = tk.Menu(self.root, tearoff=0)
        self.table_popup.add_command(label="Use This", command=self.table_popup_select)
        self.table_popup.add_command(label="Do Not Use This", command=self.table_popup_unselect)
        self.table_popup.add_separator()
        self.table_popup.add_command(label="Test Speed", command=self.table_popup_speed)

        self.table['columns'] = ('NAME', 'TYPE', 'ADDR', 'PORT', 'CIPHER', 'NETWORK', 'SECURITY', 'SERVERNAME')

        self.table.column("#0", anchor=tk.CENTER, width=40)
        self.table.column("NAME", anchor=tk.CENTER, width=60)
        self.table.column("TYPE", anchor=tk.CENTER, width=60)
        self.table.column("ADDR", anchor=tk.CENTER, width=60)
        self.table.column("PORT", anchor=tk.CENTER, width=60)
        self.table.column("CIPHER", anchor=tk.CENTER, width=80)
        self.table.column("NETWORK", anchor=tk.CENTER, width=80)
        self.table.column("SECURITY", anchor=tk.CENTER, width=80)
        self.table.column("SERVERNAME", anchor=tk.CENTER, width=100)

        self.table.heading("#0", text="", anchor=tk.CENTER)
        self.table.heading("NAME", text="NAME", anchor=tk.CENTER)
        self.table.heading("TYPE", text="TYPE", anchor=tk.CENTER)
        self.table.heading("ADDR", text="ADDR", anchor=tk.CENTER)
        self.table.heading("PORT", text="PORT", anchor=tk.CENTER)
        self.table.heading("CIPHER", text="CIPHER", anchor=tk.CENTER)
        self.table.heading("NETWORK", text="NETWORK", anchor=tk.CENTER)
        self.table.heading("SECURITY", text="SECURITY", anchor=tk.CENTER)
        self.table.heading("SERVERNAME", text="SERVERNAME", anchor=tk.CENTER)

        self.table.bind("<Button-3>", self.do_table_popup)

    def click_update_subscription(self):
        if self.http_get:
            print(f'Subscriptions are currently being updated')
            return

        subscription_url = self.editor0.get()
        print(f'Start update subscription: {subscription_url}')
        self.http_get = ChildProcHttpGet(subscription_url)
        self.root.after(100, func=self.check_update_subscription)

    def check_update_subscription(self):
        if self.http_get and not self.http_get.finish():
            self.root.after(100, func=self.check_update_subscription)
            print("Wait...")
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

    def do_table_popup(self, event):
        self.cur_popup = int(self.table.identify_row(event.y))
        self.table_popup.post(event.x_root, event.y_root)

    def table_popup_select(self):
        if self.cur_popup < 0 or self.cur_popup >= len(self.svr_lst):
            return

        cur_json = self.config_obj.gen_json(self.svr_lst[self.cur_popup])
        self.cur_svr = self.cur_popup
        self.update_svr_lst_to_ui()

    def table_popup_unselect(self):
        if self.cur_popup < 0 or self.cur_popup >= len(self.svr_lst):
            return

        if self.cur_svr == self.cur_popup:
            self.cur_svr = -1
            self.update_svr_lst_to_ui()

    def table_popup_speed(self):
        pass

    def start_v2ray(self):
        pass

    def stop_v2ray(self):
        pass


if __name__ == '__main__':
    ui_main = UIMain()
    ui_main.root.mainloop()
